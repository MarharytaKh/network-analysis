#!/usr/bin/env python3
# analyzer.py - разбирает pcap и считает DNS / TCP / TLS / SIP
# запуск: python3 analyzer.py captures/test01.pcap
#         python3 analyzer.py captures/test01.pcap --json out.json
# pcapng пока не умеет, сохраняй из wireshark как "pcap" (libpcap)

import argparse
import json
import socket
import struct
from collections import Counter


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, nano = ">", True
    else:
        raise SystemExit("не похоже на pcap (pcapng не поддерживается)")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_s, ts_f, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        div = 1e9 if nano else 1e6
        yield ts_s + ts_f / div, linktype, pkt


def decode(ts, linktype, pkt):
    # только ethernet и только ipv4, остальное пропускаем
    if linktype != 1 or len(pkt) < 14:
        return None
    etype = struct.unpack("!H", pkt[12:14])[0]
    off = 14
    if etype == 0x8100:  # один vlan тег
        etype = struct.unpack("!H", pkt[16:18])[0]
        off = 18
    if etype != 0x0800:
        return None

    ip = pkt[off:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    p = {
        "ts": ts,
        "src": socket.inet_ntoa(ip[12:16]),
        "dst": socket.inet_ntoa(ip[16:20]),
        "ipproto": proto,
        "len": len(pkt),
    }
    body = ip[ihl:]

    if proto == 6 and len(body) >= 20:
        sport, dport, seq, ack = struct.unpack("!HHII", body[:12])
        doff = (body[12] >> 4) * 4
        p.update(kind="tcp", sport=sport, dport=dport, seq=seq,
                 ack=ack, flags=body[13], payload=body[doff:])
    elif proto == 17 and len(body) >= 8:
        sport, dport = struct.unpack("!HH", body[:4])
        p.update(kind="udp", sport=sport, dport=dport, payload=body[8:])
    else:
        p.update(kind="other", payload=b"")
    return p


def dns_question(buf):
    # имя без компрессии, в вопросах она обычно не нужна
    tid, flags, _qd = struct.unpack("!HHH", buf[:6])
    off = 12
    labels = []
    while off < len(buf) and buf[off] != 0:
        ln = buf[off]
        if ln & 0xC0:
            break
        labels.append(buf[off + 1:off + 1 + ln].decode(errors="replace"))
        off += ln + 1
    qtype = None
    if off + 3 <= len(buf):
        qtype = struct.unpack("!H", buf[off + 1:off + 3])[0]
    return tid, flags, ".".join(labels), qtype


def sip_headers(text):
    h = {}
    for line in text.split("\r\n")[1:]:
        if not line:
            break
        if ":" in line:
            k, v = line.split(":", 1)
            h[k.strip().lower()] = v.strip()
    return h


def pct(vals, q):
    s = sorted(vals)
    i = min(len(s) - 1, int(round(q * (len(s) - 1))))
    return s[i]


def summ(vals):
    if not vals:
        return {"n": 0}
    return {
        "n": len(vals),
        "min": round(min(vals), 3),
        "median": round(pct(vals, 0.5), 3),
        "p95": round(pct(vals, 0.95), 3),
        "max": round(max(vals), 3),
    }


def analyze(path):
    st = {
        "packets": 0, "bytes": 0, "start": None, "end": None,
        "ip_kinds": Counter(),
        "dns_q": 0, "dns_r": 0, "dns_qtypes": Counter(), "dns_rcode": Counter(),
        "dns_rtt": [],
        "tcp_rtt": [],
        "tls_hello": Counter(), "tls_hs_rtt": [],
        "sip_req": Counter(), "sip_resp": Counter(), "sip_rtt": [],
    }

    dns_pending = {}
    tcp_sent = {}
    tls_pending = {}
    sip_pending = {}

    for ts, lt, raw in read_pcap(path):
        st["packets"] += 1
        st["bytes"] += len(raw)
        if st["start"] is None:
            st["start"] = ts
        st["end"] = ts

        p = decode(ts, lt, raw)
        if p is None:
            st["ip_kinds"]["non-ipv4"] += 1
            continue
        st["ip_kinds"][p["kind"]] += 1

        # ---- DNS (udp 53) ----
        if p["kind"] == "udp" and 53 in (p["sport"], p["dport"]) and len(p["payload"]) >= 12:
            tid, flags, name, qtype = dns_question(p["payload"])
            if (flags & 0x8000) == 0:
                st["dns_q"] += 1
                st["dns_qtypes"][qtype] += 1
                dns_pending.setdefault((p["src"], p["dst"], tid), ts)
            else:
                st["dns_r"] += 1
                st["dns_rcode"][flags & 0xF] += 1
                key = (p["dst"], p["src"], tid)
                if key in dns_pending:
                    st["dns_rtt"].append((ts - dns_pending.pop(key)) * 1000)

        # ---- TCP RTT + TLS handshake ----
        elif p["kind"] == "tcp":
            pl = p["payload"]
            flow = (p["src"], p["sport"], p["dst"], p["dport"])
            rflow = (p["dst"], p["dport"], p["src"], p["sport"])

            if pl:
                end = (p["seq"] + len(pl)) & 0xFFFFFFFF
                tcp_sent.setdefault((flow, end), ts)

            # ack-бит = 0x10. ack подтверждает данные обратного потока
            if p["flags"] & 0x10 and (rflow, p["ack"]) in tcp_sent:
                st["tcp_rtt"].append((ts - tcp_sent.pop((rflow, p["ack"]))) * 1000)

            # TLS record: type 0x16 (handshake), версия 0x03xx, дальше тип сообщения
            if len(pl) >= 6 and pl[0] == 0x16 and pl[1] == 0x03:
                hs = pl[5]
                if hs == 1:
                    st["tls_hello"]["ClientHello"] += 1
                    tls_pending.setdefault(flow, ts)
                elif hs == 2:
                    st["tls_hello"]["ServerHello"] += 1
                    if rflow in tls_pending:
                        st["tls_hs_rtt"].append((ts - tls_pending.pop(rflow)) * 1000)

        # ---- SIP (5060, udp или tcp) ----
        if p["kind"] in ("udp", "tcp") and 5060 in (p.get("sport"), p.get("dport")):
            try:
                text = p["payload"].decode("ascii")
            except UnicodeDecodeError:
                text = ""
            first = text.split("\r\n", 1)[0]
            if "SIP/2.0" not in first:
                continue
            hdr = sip_headers(text)
            callid = hdr.get("call-id", hdr.get("i", ""))
            cparts = hdr.get("cseq", "").split()
            cmethod = cparts[1] if len(cparts) == 2 else "?"

            if first.startswith("SIP/2.0"):
                code = int(first.split()[1])
                st["sip_resp"][code] += 1
                # финальный ответ (>= 200) закрывает запрос
                if code >= 200 and (callid, cmethod) in sip_pending:
                    st["sip_rtt"].append((ts - sip_pending.pop((callid, cmethod))) * 1000)
            else:
                method = first.split()[0]
                st["sip_req"][method] += 1
                sip_pending.setdefault((callid, cmethod), ts)

    st["duration_s"] = round((st["end"] or 0) - (st["start"] or 0), 3)
    return st


def print_report(st, path):
    print(f"файл: {path}")
    print(f"пакетов: {st['packets']}, байт: {st['bytes']}, длительность: {st['duration_s']} s")
    print("кто что несет:", dict(st["ip_kinds"]))
    print()
    print("DNS")
    print(f"  запросов {st['dns_q']}, ответов {st['dns_r']}")
    print("  qtype:", dict(st["dns_qtypes"]))
    print("  rcode:", dict(st["dns_rcode"]))
    print("  RTT:", summ(st["dns_rtt"]))
    print()
    print("TCP")
    print("  RTT (data->ack):", summ(st["tcp_rtt"]))
    print()
    print("TLS")
    print("  hello:", dict(st["tls_hello"]))
    print("  ClientHello->ServerHello:", summ(st["tls_hs_rtt"]))
    print()
    print("SIP")
    print("  запросы:", dict(st["sip_req"]))
    print("  ответы:", dict(st["sip_resp"]))
    print("  RTT до финального ответа:", summ(st["sip_rtt"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--json", help="куда сохранить сводку")
    args = ap.parse_args()

    st = analyze(args.pcap)
    print_report(st, args.pcap)

    if args.json:
        out = {}
        for k, v in st.items():
            if isinstance(v, Counter):
                out[k] = {str(a): b for a, b in v.items()}
            elif isinstance(v, list):
                out[k] = summ(v)
            else:
                out[k] = v
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"\njson -> {args.json}")


if __name__ == "__main__":
    main()
