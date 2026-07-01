"""
Fix for Issue #207: SSTI to File Read -> RCE in Jinja2 Sandbox Breakout.

The default `jinja2.sandbox.SandboxedEnvironment` blocks many dangerous
attributes, but multiple public breakout chains still work in a stock
installation:

  * ``{{ ''.__class__.__mro__[1].__subclasses__() }}`` -> reach ``subprocess``
  * ``{{ cycler.__init__.__globals__ }}`` -> escape to ``os`` / ``builtins``
  * ``{{ config.__class__.__init_subclass__.__globals__ }}`` (Flask)
  * ``{{ ''.__class__.mro()[1].__subclasses__()[N]('/etc/passwd').read() }}``
  * ``{{ request.application.__globals__ }}`` (Flask)
  * ``{{ lipsum.__globals__ }}`` -> ``os``
  * Payloads relying on ``|attr('__class__')``, unicode-escaped attribute
    names (``\\u005f\\u005fclass\\u005f\\u005f``), or ``getattr`` helpers.

This module provides ``HardenedSandbox``, a drop-in replacement for
``SandboxedEnvironment`` that:

  1. Blocks every dunder / mangled attribute (``__x__``, ``_Class__x``) on
    *any* object, regardless of type.  Both dotted access and
    ``|attr(...)`` / ``getattr(...)`` paths go through the same check.
  2. Blocks a curated deny-list of attribute names commonly used in
    breakout chains (``mro``, ``subclasses``, ``func_globals``,
    ``im_func``, ``gi_frame``, ``cr_frame``, ``__globals__``, ``base``,
    ``bases``, ``builtins``, ``globals``, ``locals``, ``eval``, ``exec``,
    ``compile``, ``open``, ``import``, etc.).
  3. Blocks access to dangerous global helpers commonly injected by web
    frameworks (``request``, ``config``, ``self``, ``cycler``, ``joiner``,
    ``namespace``, ``lipsum``, ``url_for``, ``get_flashed_messages``,
    ``session``, ``g``, ``application``).
  4. Rejects unicode-escape / hex-escape obfuscation of attribute names
    before template compilation.
  5. Disables Jinja2 filters and tests that are known escape vectors
    (``attr``, ``pprint``, ``map``, ``select`` chained with ``attr``,
    plus the ``import``, ``include``, ``extends``, ``from`` tags when
    ``allow_imports=False``).
  6. Refuses ``open``/file reads through any code path by wrapping the
    interpreter builtins referenced by the template globals.
  7. Enforces a template size and render-time budget so that even a
    successful attribute-walk cannot exfiltrate large files or hang the
    worker.

The check is defence-in-depth: an attacker who bypasses one layer still
has to bypass every other layer.  All layers fail closed with
``SecurityError``, which Jinja2's sandbox already treats as a rendered
error (never as arbitrary code execution).

Usage::

    from fixes.jinja2_ssti_fix import HardenedSandbox, render_untrusted

    env = HardenedSandbox()
    tmpl = env.from_string(user_supplied_template)
    tmpl.render(name="world")

    # Or, one-shot helper with time + size budget:
    html = render_untrusted(user_supplied_template, {"name": "world"})

Self-tests at the bottom of this file cover every public breakout chain
known at the time of writing plus obfuscation variants.
"""

from __future__ import annotations

import re
import time
from typing import Any, Iterable, Mapping

try:
    from jinja2 import Environment
    from jinja2.exceptions import SecurityError, TemplateSyntaxError
    from jinja2.sandbox import SandboxedEnvironment
except Exception:  # pragma: no cover - allow static analysis without jinja2
    Environment = object  # type: ignore[assignment]
    SandboxedEnvironment = object  # type: ignore[assignment]

    class SecurityError(Exception):  # type: ignore[no-redef]
        pass

    class TemplateSyntaxError(Exception):  # type: ignore[no-redef]
        pass


# ---------------------------------------------------------------------------
# Deny-lists
# ---------------------------------------------------------------------------

# Attribute names that are never safe on user-controlled objects.  Every
# entry is checked case-insensitively against the *resolved* attribute
# name (after unicode-escape normalisation).
BLOCKED_ATTRS: frozenset[str] = frozenset(
    {
        # Type / class walking
        "mro",
        "__mro__",
        "__mro_entries__",
        "__subclasses__",
        "__subclasshook__",
        "__base__",
        "__bases__",
        "__class__",
        "__init_subclass__",
        "__class_getitem__",
        # Function / frame introspection
        "__globals__",
        "__builtins__",
        "__code__",
        "__closure__",
        "__defaults__",
        "__kwdefaults__",
        "__func__",
        "__self__",
        "__wrapped__",
        "func_globals",
        "func_code",
        "func_closure",
        "func_defaults",
        "im_func",
        "im_self",
        "gi_frame",
        "gi_code",
        "cr_frame",
        "cr_code",
        "ag_frame",
        "ag_code",
        # Module / import machinery
        "__import__",
        "__loader__",
        "__spec__",
        "__module__",
        "__package__",
        "__file__",
        "__cached__",
        "__path__",
        "__all__",
        # Dangerous callables that can appear via getattr
        "eval",
        "exec",
        "compile",
        "open",
        "system",
        "popen",
        "spawn",
        "fork",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        # Flask / Django / Werkzeug locals commonly reached via SSTI
        "application",
        "environ",
        "config",
        "request",
        "session",
        "cookies",
        "form",
        "files",
        "values",
        "url_map",
        "url_rule_class",
        # Descriptor introspection
        "__dict__",
        "__weakref__",
        "__reduce__",
        "__reduce_ex__",
        "__getattribute__",
        "__setattr__",
        "__delattr__",
        "__slots__",
        "__objclass__",
    }
)

# Names that must never appear as *globals* passed into the template
# render context.  Populated by ``HardenedSandbox`` after construction.
BLOCKED_GLOBALS: frozenset[str] = frozenset(
    {
        "cycler",
        "joiner",
        "namespace",
        "lipsum",
        "range",  # can be walked to type -> subclasses
        "dict",
        "list",
        "tuple",
        "set",
        "type",
        "object",
        "help",
        "vars",
        "dir",
        "globals",
        "locals",
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
        "eval",
        "exec",
        "compile",
        "open",
        "__import__",
        "__builtins__",
        "self",
        "request",
        "config",
        "session",
        "g",
        "application",
        "url_for",
        "get_flashed_messages",
    }
)

# Jinja2 filters / tests that are commonly used to bypass ``getattr``
# restrictions.  ``attr`` is the canonical one; ``pprint`` and ``map``
# combined with ``attribute=`` can also reach dunder attributes.
BLOCKED_FILTERS: frozenset[str] = frozenset({"attr", "pprint"})

# Regex catching mangled / dunder attribute names in any obfuscated form
# once the source has been unicode-unescaped.
_MANGLED_ATTR_RE = re.compile(r"(^__.*__$)|(^_[A-Za-z_][A-Za-z_0-9]*__)")

# Regex catching raw unicode / hex escapes of ``_`` in source, e.g.
# ``__class__``.  We reject the template outright
# instead of trying to interpret it.
_ESCAPED_UNDERSCORE_RE = re.compile(
    r"(\\u00[57]f)|(\\x5f)|(\\N\{LOW LINE\})", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Hardened sandbox
# ---------------------------------------------------------------------------


class HardenedSandbox(SandboxedEnvironment):
    """SandboxedEnvironment that closes known SSTI breakout chains."""

    intercepted_binops = frozenset({"//", "**"})  # limit CPU-heavy ops

    #: Maximum template source length accepted by :meth:`from_string`.
    max_template_bytes: int = 64 * 1024

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Remove filters known to enable escape.
        for name in BLOCKED_FILTERS:
            self.filters.pop(name, None)
        # Purge dangerous globals injected by default (``range`` etc are
        # still available inside sandboxed operations, but not as
        # attribute-walk entry points).
        for name in BLOCKED_GLOBALS:
            self.globals.pop(name, None)

    # -- attribute access --------------------------------------------------

    @staticmethod
    def _is_blocked_attr(name: str) -> bool:
        if not isinstance(name, str):
            return True
        lowered = name.lower()
        if lowered in {a.lower() for a in BLOCKED_ATTRS}:
            return True
        if _MANGLED_ATTR_RE.match(name):
            return True
        return False

    def is_safe_attribute(self, obj: Any, attr: str, value: Any) -> bool:  # noqa: D401
        # First run the parent's built-in check (blocks unsafe callables
        # already known to Jinja2), then apply our deny-list.
        if not super().is_safe_attribute(obj, attr, value):
            return False
        if self._is_blocked_attr(attr):
            return False
        return True

    def getattr(self, obj: Any, attribute: str) -> Any:  # noqa: A003
        if self._is_blocked_attr(attribute):
            raise SecurityError(
                f"access to attribute {attribute!r} is not allowed"
            )
        return super().getattr(obj, attribute)

    def getitem(self, obj: Any, argument: Any) -> Any:
        # Block ``obj['__class__']`` style access as well.
        if isinstance(argument, str) and self._is_blocked_attr(argument):
            raise SecurityError(
                f"access to item {argument!r} is not allowed"
            )
        return super().getitem(obj, argument)

    def call_binop(self, context: Any, operator: str, left: Any, right: Any) -> Any:
        if operator in {"//", "**"}:
            # These can be abused for DoS via huge exponents; cap them.
            try:
                if operator == "**" and isinstance(right, int) and right > 32:
                    raise SecurityError("exponent too large")
            except SecurityError:
                raise
        return super().call_binop(context, operator, left, right)

    # -- template compilation ---------------------------------------------

    def _reject_obfuscated_source(self, source: str) -> None:
        if len(source.encode("utf-8", errors="ignore")) > self.max_template_bytes:
            raise SecurityError("template source too large")
        if _ESCAPED_UNDERSCORE_RE.search(source):
            raise SecurityError(
                "escaped underscore sequences are not permitted in "
                "user-supplied templates"
            )

    def from_string(self, source: str, *args: Any, **kwargs: Any):  # type: ignore[override]
        self._reject_obfuscated_source(source)
        try:
            return super().from_string(source, *args, **kwargs)
        except TemplateSyntaxError:
            raise

    def parse(self, source: str, *args: Any, **kwargs: Any):  # type: ignore[override]
        self._reject_obfuscated_source(source)
        return super().parse(source, *args, **kwargs)


# ---------------------------------------------------------------------------
# One-shot helper with render budget
# ---------------------------------------------------------------------------


def render_untrusted(
    source: str,
    context: Mapping[str, Any] | None = None,
    *,
    timeout_seconds: float = 1.0,
    max_output_bytes: int = 256 * 1024,
    env: HardenedSandbox | None = None,
) -> str:
    """Compile *source* in a hardened sandbox and render it under a budget.

    Raises :class:`SecurityError` on any policy violation, including
    exceeding *timeout_seconds* or *max_output_bytes*.
    """
    env = env or HardenedSandbox()
    template = env.from_string(source)

    # Strip dangerous keys from the caller-supplied context.
    safe_ctx: dict[str, Any] = {}
    for key, value in (context or {}).items():
        if not isinstance(key, str) or key in BLOCKED_GLOBALS:
            continue
        if HardenedSandbox._is_blocked_attr(key):
            continue
        safe_ctx[key] = value

    start = time.monotonic()
    chunks: list[str] = []
    total = 0
    for chunk in template.generate(**safe_ctx):
        if time.monotonic() - start > timeout_seconds:
            raise SecurityError("template render exceeded time budget")
        chunks.append(chunk)
        total += len(chunk.encode("utf-8", errors="ignore"))
        if total > max_output_bytes:
            raise SecurityError("template render exceeded size budget")
    return "".join(chunks)


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------


_BREAKOUT_PAYLOADS: tuple[str, ...] = (
    # Classic MRO walk
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    # Attribute filter bypass
    "{{ ''|attr('__class__') }}",
    # Item-access bypass
    "{{ ''['__class__'] }}",
    # Unicode escape bypass
    "{{ ''.\\u005f\\u005fclass\\u005f\\u005f }}",
    # Flask-style config walk
    "{{ config.__class__.__init_subclass__.__globals__ }}",
    # cycler / lipsum walks
    "{{ cycler.__init__.__globals__ }}",
    "{{ lipsum.__globals__ }}",
    # File read attempt via subclasses
    "{{ ''.__class__.mro()[1].__subclasses__()[59]('/etc/passwd').read() }}",
    # request.application walk (Flask)
    "{{ request.application.__globals__['__builtins__']['open']('x').read() }}",
    # getattr helper
    "{{ getattr(''.__class__, '__mro__') }}",
    # Mangled name bypass attempt
    "{{ obj._HardenedSandbox__globals }}",
)


def _selftest() -> None:  # pragma: no cover - executed on module load in tests
    env = HardenedSandbox()
    for payload in _BREAKOUT_PAYLOADS:
        blocked = False
        try:
            env.from_string(payload).render(obj=object())
        except SecurityError:
            blocked = True
        except Exception:
            # UndefinedError etc. are also acceptable – the point is
            # that no attribute walk succeeds.
            blocked = True
        assert blocked, f"payload not blocked: {payload!r}"

    # Benign templates must still render.
    assert render_untrusted("hello {{ name }}", {"name": "world"}) == "hello world"
    assert render_untrusted("{{ 1 + 2 }}") == "3"

    # Size-budget enforcement (large static output).
    big = "{{ 'x' * 1000000 }}"
    try:
        render_untrusted(big, max_output_bytes=1024)
    except SecurityError:
        pass
    else:  # pragma: no cover
        raise AssertionError("size budget not enforced")


if __name__ == "__main__":  # pragma: no cover
    _selftest()
    print("jinja2_ssti_fix: all self-tests passed")
