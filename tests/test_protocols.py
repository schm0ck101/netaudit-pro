"""Briques protocolaires maison, testées hors réseau sur des messages construits
octet par octet selon les normes (vecteurs officiels quand ils existent)."""
import os
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("NETAUDIT_DATA_DIR", str(Path(os.environ.get("TEMP", "/tmp")) / "netaudit-tests"))

from netaudit.net import aes, dhcp, dnsmsg, names, snmp, ssh  # noqa: E402
from netaudit.scan.runner import parse_ranges  # noqa: E402


def test_aes_fips197_and_cfb_nist():
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    assert aes.AES(k).encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    ct = aes.cfb_encrypt(k, iv, pt)
    assert ct.hex() == "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
    assert aes.cfb_decrypt(k, iv, ct) == pt
    assert aes.cfb_decrypt(k, iv, aes.cfb_encrypt(k, iv, b"abc")) == b"abc"      # bloc partiel


def test_snmp_key_localisation_rfc3414():
    eid = bytes.fromhex("000000000000000000000002")
    assert snmp.password_to_key("maplesyrup", eid, "MD5").hex() == "526f5eed9fcce26f8964c2930787d82b"
    assert snmp.password_to_key("maplesyrup", eid, "SHA").hex() == "6695febc9288e36282235fc7151f128497b38f3f"


def test_snmp_ber_roundtrip():
    for v in (0, 1, 127, 128, 255, 256, -1, -129, 2**31 - 1, 2**40):
        tag, c, _ = snmp.dec(snmp.enc_int(v))
        assert snmp.dec_value(tag, c) == v
    for oid in ("1.3.6.1.2.1.1.1.0", "1.0.8802.1.1.2.1.4.1.1.9", "1.3.6.1.4.1.311.21.1234567.1"):
        tag, c, _ = snmp.dec(snmp.enc_oid(oid))
        assert snmp.dec_oid(c) == oid
    pdu = snmp._pdu(snmp.GETBULK, 42, ["1.3.6.1.2.1.2.2.1.2"], 0, 25)
    tag, rid, a, b, vbs = snmp._parse_pdu(pdu)
    assert (tag, rid, a, b, vbs[0][0]) == (snmp.GETBULK, 42, 0, 25, "1.3.6.1.2.1.2.2.1.2")
    long = snmp.tlv(snmp.OCTETS, b"x" * 300)          # longueur sur 2 octets
    assert snmp.dec(long)[1] == b"x" * 300
    assert snmp.dec_value(snmp.COUNTER64, (2**63 + 5).to_bytes(9, "big")) == 2**63 + 5
    assert snmp.dec_value(snmp.IPADDR, bytes([10, 0, 0, 1])) == "10.0.0.1"


def test_snmp_credential_label_hides_secret():
    assert "public" not in snmp.Credential("2c", "public").label()
    assert "motdepasse" not in snmp.Credential("3", "", "u", "SHA", "motdepasse", "AES", "motdepasse").label()


def _dhcp_offer(xid, server, offered, router, dns, lease):
    pkt = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, socket.inet_aton(offered),
                      socket.inet_aton(server), b"\0" * 4, b"\x00" * 16, b"\0" * 64, b"\0" * 128)
    o = b"\x63\x82\x53\x63" + bytes([53, 1, 2, 54, 4]) + socket.inet_aton(server) + bytes([1, 4]) + socket.inet_aton("255.255.255.0")
    o += bytes([3, 4]) + socket.inet_aton(router) + bytes([6, 8]) + b"".join(socket.inet_aton(d) for d in dns)
    o += bytes([51, 4]) + struct.pack("!I", lease) + bytes([15, 9]) + b"corp.test" + b"\xff"
    return pkt + o


def test_dhcp_discover_and_offer_parsing():
    d = dhcp.build_discover(bytes.fromhex("aabbccddeeff"), 0x1234)
    assert d[0] == 1 and struct.unpack_from("!I", d, 4)[0] == 0x1234 and d[28:34] == bytes.fromhex("aabbccddeeff")
    assert len(d) >= 300 and b"\x35\x01\x01" in d               # option 53 = DISCOVER
    r = dhcp.parse(_dhcp_offer(0x1234, "10.0.0.10", "10.0.0.150", "10.0.0.1", ["10.0.0.10", "10.0.0.11"], 28800), 0x1234)
    assert r["type"] == "offer" and r["server_id"] == "10.0.0.10" and r["offered_ip"] == "10.0.0.150"
    assert r["router"] == ["10.0.0.1"] and r["dns"] == ["10.0.0.10", "10.0.0.11"] and r["lease"] == 28800 and r["domain"] == "corp.test"
    assert dhcp.parse(_dhcp_offer(0x9999, "10.0.0.10", "10.0.0.150", "10.0.0.1", [], 60), 0x1234) is None   # autre transaction


def test_dns_message_build_and_parse_with_compression():
    q = dnsmsg.build_query("www.exemple.fr", "A", qid=7)
    assert q[:2] == b"\x00\x07" and b"\x03www\x07exemple\x02fr\x00" in q
    # réponse : question + A + CNAME compressé + SRV + TXT
    head = struct.pack("!HHHHHH", 7, 0x8180, 1, 4, 0, 0)
    qn = b"\x03www\x07exemple\x02fr\x00"
    body = qn + struct.pack("!HH", 1, 1)
    body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 1])
    body += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 6) + b"\x03cdn\xc0\x10"
    srv = struct.pack("!HHH", 0, 100, 389) + b"\x03dc1\xc0\x10"
    body += b"\xc0\x0c" + struct.pack("!HHIH", 33, 1, 60, len(srv)) + srv
    txt = b"\x05a=b c\x03x=y"
    body += b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt)) + txt
    r = dnsmsg.parse(head + body)
    vals = {x["type"]: x["value"] for x in r["records"]}
    assert r["rcode"] == "OK" and r["ra"]
    assert vals["A"] == "192.0.2.1" and vals["CNAME"] == "cdn.exemple.fr"
    assert vals["SRV"] == {"priority": 0, "weight": 100, "port": 389, "target": "dc1.exemple.fr"}
    assert vals["TXT"] == ["a=b c", "x=y"]
    assert dnsmsg.reverse_name("10.1.2.3") == "3.2.1.10.in-addr.arpa"


def test_netbios_node_status_parsing():
    head = struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0)
    name = b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    entries = [(b"SRV-FICHIERS", 0x00, 0x0400), (b"CORP", 0x00, 0x8400), (b"SRV-FICHIERS", 0x20, 0x0400), (b"CORP", 0x1C, 0x8400)]
    rd = bytes([len(entries)]) + b"".join(n.ljust(15, b" ") + bytes([s]) + struct.pack("!H", f) for n, s, f in entries)
    rd += bytes.fromhex("00155d010203") + b"\0" * 40
    pkt = head + name + struct.pack("!HHIH", 0x21, 1, 0, len(rd)) + rd
    r = names._nb_parse(pkt)
    assert r["name"] == "SRV-FICHIERS" and r["workgroup"] == "CORP" and r["file_server"] and r["dc"]
    assert r["mac"] == "00:15:5d:01:02:03"


def test_ranges_parsing():
    nets, spans, bad = parse_ranges(["10.0.20.0/24", "10.0.30.10-10.0.30.50", "10.0.40.5-9", "192.168.1.7", "n'importe quoi"])
    assert [str(n) for n in nets] == ["10.0.20.0/24", "192.168.1.7/32"]
    assert len(spans) == 2 and spans[1][1] - spans[1][0] == 4
    assert bad == ["n'importe quoi"]


def test_ssh_profiles_and_safe_commands():
    assert ssh.guess_profile("HP J9776A 2530-24G Switch, revision YA.16.10.0012") == "procurve"
    assert ssh.guess_profile("Aruba JL260A 2930F-24G-4SFP Switch, revision WC.16.11.0002") == "procurve"
    assert ssh.guess_profile("ArubaOS-CX Aruba 6300M") == "aruba-cx"
    assert ssh.guess_profile("Cisco IOS Software, C2960X Software") == "cisco-ios"
    assert ssh.guess_profile("Cisco Small Business CBS350-24P") == "cisco-sb"
    assert ssh.guess_profile("RouterOS CRS326-24G-2S+") == "mikrotik"
    assert ssh.guess_profile("", "SSH-2.0-OpenSSH_9.6") == "linux"
    for setup, cmds in ssh.PROFILES.values():
        for c in setup + cmds:
            assert c.startswith(ssh.SAFE_PREFIX), c
            first = c.split()[0].lower()
            assert first not in ("configure", "conf", "write", "copy", "reload", "set", "delete", "erase", "rm", "reboot",
                                 "clear", "no") or c == "no page", c


def test_x509_parser_on_generated_certificates():
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    from netaudit.net._x509 import parse_cert
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    for key, bits in ((rsa.generate_private_key(65537, 1024), 1024), (ec.generate_private_key(ec.SECP256R1()), None)):
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "switch.corp.test"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Corp")])
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
                .serial_number(1234).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
                .sign(key, hashes.SHA256()))
        r = parse_cert(cert.public_bytes(serialization.Encoding.DER))
        assert r["subject"] == "switch.corp.test" and r["self_signed"]
        assert r["not_after"].startswith("2026-01-31")
        assert r["key_bits"] == bits and r["key_type"] == ("RSA" if bits else "ECDSA")


def test_ssh_log_scanner_ignores_non_log_commands():
    ev = ssh.scan_logs({"show interfaces brief": "port 3 loop detected", "show logging": "nothing to see"})
    assert ev == {}
