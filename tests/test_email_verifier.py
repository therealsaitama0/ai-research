import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_verifier import verify_spf, verify_dkim


def test_verify_spf_returns_bool():
    fake_response = bytearray(
        b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x10\x00\x01"
        b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x01\x00\x07"
        b"\x06v=spf1"
    )
    with patch("socket.socket") as mock_socket:
        instance = mock_socket.return_value
        instance.recvfrom.return_value = (fake_response, ("8.8.8.8", 53))
        result = verify_spf("example.com")
    assert result is True


def test_verify_spf_without_spf_record():
    fake_response = bytearray(
        b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x10\x00\x01"
    )
    with patch("socket.socket") as mock_socket:
        instance = mock_socket.return_value
        instance.recvfrom.return_value = (fake_response, ("8.8.8.8", 53))
        result = verify_spf("example.com")
    assert result is False


def test_verify_dkim_returns_bool():
    fake_response = bytearray(
        b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x10\x00\x01"
        b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x01\x00\x03"
        b"\x02v="
    )
    with patch("socket.socket") as mock_socket:
        instance = mock_socket.return_value
        instance.recvfrom.return_value = (fake_response, ("8.8.8.8", 53))
        result = verify_dkim("example.com", "default")
    assert result is True


def test_verify_dkim_without_record():
    fake_response = bytearray(
        b"\x00\x01\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x10\x00\x01"
    )
    with patch("socket.socket") as mock_socket:
        instance = mock_socket.return_value
        instance.recvfrom.return_value = (fake_response, ("8.8.8.8", 53))
        result = verify_dkim("example.com", "default")
    assert result is False


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
