"""Email verification module to prevent email spoofing via SPF/DKIM validation."""

import socket
import struct


def _build_dns_query(domain, qtype=16):
    transaction_id = b"\x00\x01"
    flags = b"\x01\x00"
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    return transaction_id + flags + qdcount + ancount + nscount + arcount + question


def _parse_name(data, offset):
    labels = []
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", data[offset : offset + 2])[0] & 0x3FFF
            sub_labels, _ = _parse_name(data, pointer)
            labels.append(sub_labels)
            return ".".join(labels), offset + 2
        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _parse_txt_records(data):
    if len(data) < 12:
        return []
    offset = 12
    qdcount = struct.unpack(">H", data[4:6])[0]
    for _ in range(qdcount):
        _, offset = _parse_name(data, offset)
        offset += 4
    ancount = struct.unpack(">H", data[6:8])[0]
    records = []
    for _ in range(ancount):
        _, offset = _parse_name(data, offset)
        rtype = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2 + 2 + 4
        rdlen = struct.unpack(">H", data[offset : offset + 2])[0]
        offset += 2
        if rtype == 16:
            txt = b""
            end = offset + rdlen
            while offset < end:
                slen = data[offset]
                offset += 1
                txt += data[offset : offset + slen]
                offset += slen
            records.append(txt.decode("utf-8", errors="replace"))
        else:
            offset += rdlen
    return records


def _dns_txt_query(domain):
    query = _build_dns_query(domain, 16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, ("8.8.8.8", 53))
    data, _ = sock.recvfrom(4096)
    sock.close()
    return _parse_txt_records(data)


def verify_spf(domain):
    """Return True if domain publishes a valid SPF record."""
    try:
        records = _dns_txt_query(domain)
        return any("v=spf1" in r.lower() for r in records)
    except Exception:
        return False


def verify_dkim(domain, selector="default"):
    """Return True if domain publishes a valid DKIM record for the selector."""
    name = f"{selector}._domainkey.{domain}"
    try:
        records = _dns_txt_query(name)
        return len(records) > 0
    except Exception:
        return False
