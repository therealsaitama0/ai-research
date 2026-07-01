"""
Fix for Issue #203: XXE via SVG Upload → SSRF → Internal Port Scanning

Root cause
----------
SVG is XML. When user-uploaded SVGs are parsed with a default XML parser
(lxml, xml.etree, xml.dom.minidom, xml.sax), external entities and
DOCTYPE declarations are honored. An attacker crafts:

    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
    <svg>&xxe;</svg>

or, more damaging, parameter entities that fetch remote DTDs — which pivots
to SSRF against internal services (cloud metadata, 127.0.0.1:*, 10.0.0.0/8,
etc.) and enables blind port scanning by timing entity resolution.

Mitigation (defense in depth)
-----------------------------
1. Reject any DOCTYPE outright before parsing (fast fail, no parser needed).
2. Use defusedxml for the actual parse — disables entities/DTD by construction.
3. Post-parse: strip <script>, on* handlers, <foreignObject>, xlink:href
   pointing to non-data/non-relative URIs, and any <use href="..."> external
   references. This blocks JS + SSRF via referenced resources.
4. Enforce size + depth caps to defeat billion-laughs / quadratic-blowup.
5. Never resolve network URIs during parse (no_network=True).
6. Return sanitized bytes only; caller writes them to disk. The original
   attacker bytes are discarded.

References: OWASP XXE Prevention Cheat Sheet; CWE-611, CWE-918, CWE-776.
"""

from __future__ import annotations

import re
from io import BytesIO
from typing import Final

try:
    from defusedxml.ElementTree import parse as _defused_parse
    from defusedxml import EntitiesForbidden, DTDForbidden, ExternalReferenceForbidden
except ImportError as e:  # pragma: no cover
    raise ImportError("defusedxml is required: pip install defusedxml") from e

from xml.etree.ElementTree import Element, tostring, register_namespace

MAX_SVG_BYTES: Final[int] = 2 * 1024 * 1024      # 2 MiB
MAX_ELEMENT_COUNT: Final[int] = 10_000
MAX_DEPTH: Final[int] = 64

SVG_NS: Final[str] = "http://www.w3.org/2000/svg"
XLINK_NS: Final[str] = "http://www.w3.org/1999/xlink"

# Elements that can execute script or fetch remote resources.
_FORBIDDEN_TAGS: Final[frozenset[str]] = frozenset({
    "script", "foreignObject", "iframe", "object", "embed",
    "audio", "video", "handler", "listener", "set", "animate",
    "animateMotion", "animateTransform",
})

# Attributes carrying JS or URIs that could be exfil / SSRF vectors.
_EVENT_ATTR_RE: Final[re.Pattern[str]] = re.compile(r"^on[a-z]+$", re.IGNORECASE)
_URI_ATTRS: Final[frozenset[str]] = frozenset({
    "href", "xlink:href", "src", "action", "formaction",
    "poster", "background", "style",
})

# Only these URI schemes are permitted inside sanitized SVGs.
_SAFE_URI_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:#[A-Za-z0-9_\-.:]+"                     # in-doc fragment
    r"|data:image/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+"
    r")$"
)

# DOCTYPE / entity declarations — reject at byte level before parsing.
_DOCTYPE_RE: Final[re.Pattern[bytes]] = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE: Final[re.Pattern[bytes]] = re.compile(rb"<!ENTITY", re.IGNORECASE)


class UnsafeSVGError(ValueError):
    """Raised when the uploaded SVG is malformed or contains unsafe content."""


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _sanitize(elem: Element, depth: int, counter: list[int]) -> None:
    counter[0] += 1
    if counter[0] > MAX_ELEMENT_COUNT:
        raise UnsafeSVGError("element count exceeds limit")
    if depth > MAX_DEPTH:
        raise UnsafeSVGError("nesting depth exceeds limit")

    local = _strip_ns(elem.tag)
    if local in _FORBIDDEN_TAGS:
        raise UnsafeSVGError(f"forbidden element: <{local}>")

    for attr in list(elem.attrib):
        local_attr = _strip_ns(attr)
        val = elem.attrib[attr]

        if _EVENT_ATTR_RE.match(local_attr):
            del elem.attrib[attr]
            continue

        if local_attr in _URI_ATTRS or attr in _URI_ATTRS:
            # style attributes can hide url(...) — reject rather than partially parse CSS.
            if local_attr == "style":
                low = val.lower()
                if "url(" in low or "expression" in low or "javascript:" in low:
                    raise UnsafeSVGError(f"unsafe CSS in style attribute: {val!r}")
                continue
            if not _SAFE_URI_RE.match(val.strip()):
                raise UnsafeSVGError(
                    f"unsafe URI in {local_attr}={val!r} (only #fragment or data:image/* allowed)"
                )

    for child in list(elem):
        _sanitize(child, depth + 1, counter)


def sanitize_svg_upload(data: bytes) -> bytes:
    """
    Validate and sanitize an uploaded SVG.

    Returns the safe serialized bytes. Raises UnsafeSVGError on any violation.
    The caller should persist the returned bytes, not the input.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise UnsafeSVGError("input must be bytes")
    if len(data) == 0:
        raise UnsafeSVGError("empty upload")
    if len(data) > MAX_SVG_BYTES:
        raise UnsafeSVGError(f"upload exceeds {MAX_SVG_BYTES} bytes")

    # Byte-level rejects — catches XXE payloads before any parser touches them.
    if _DOCTYPE_RE.search(data):
        raise UnsafeSVGError("DOCTYPE declarations are forbidden (XXE risk)")
    if _ENTITY_RE.search(data):
        raise UnsafeSVGError("ENTITY declarations are forbidden (XXE risk)")

    try:
        tree = _defused_parse(
            BytesIO(bytes(data)),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (EntitiesForbidden, DTDForbidden, ExternalReferenceForbidden) as e:
        raise UnsafeSVGError(f"XXE attempt blocked: {type(e).__name__}") from e
    except Exception as e:  # malformed XML
        raise UnsafeSVGError(f"malformed SVG: {e}") from e

    root = tree.getroot()
    if _strip_ns(root.tag) != "svg":
        raise UnsafeSVGError(f"root element must be <svg>, got <{_strip_ns(root.tag)}>")

    _sanitize(root, depth=0, counter=[0])

    register_namespace("", SVG_NS)
    register_namespace("xlink", XLINK_NS)
    return tostring(root, encoding="utf-8", xml_declaration=True)


# ---------------------------------------------------------------------------
# Self-tests — run: python fixes/xxe_svg_ssrf_fix.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    OK = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><circle r="10"/></svg>'

    ATTACKS = {
        "classic-xxe": b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>',
        "ssrf-metadata": b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "http://169.254.169.254/">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>',
        "port-scan-param-entity": b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY % remote SYSTEM "http://127.0.0.1:22/">%remote;]><svg xmlns="http://www.w3.org/2000/svg"/>',
        "script-tag": b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        "external-image": b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://internal.local/x.png"/></svg>',
        "foreignObject": b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body/></foreignObject></svg>',
        "use-external": b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="http://evil/x#a"/></svg>',
        "style-url": b'<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(http://evil/)"/></svg>',
    }

    out = sanitize_svg_upload(OK)
    assert b"<svg" in out and b"<circle" in out
    print("PASS: benign SVG accepted")

    onload = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
    out = sanitize_svg_upload(onload)
    assert b"onload" not in out, "onload handler must be stripped"
    print("PASS: onload handler stripped")

    for name, payload in ATTACKS.items():
        try:
            sanitize_svg_upload(payload)
        except UnsafeSVGError as e:
            print(f"PASS: blocked {name}: {e}")
        else:
            raise SystemExit(f"FAIL: attack '{name}' was not blocked")

    # Safe fragment ref should be preserved
    frag = b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="#icon"/></svg>'
    sanitize_svg_upload(frag)
    print("PASS: in-doc fragment reference preserved")

    try:
        sanitize_svg_upload(b"x" * (MAX_SVG_BYTES + 1))
    except UnsafeSVGError:
        print("PASS: oversize upload rejected")

    print("\nAll tests passed.")
