[README.en.md](https://github.com/user-attachments/files/34256576/README.en.md)
# net-verify

Verification tests for network traffic. Captures are recorded in Wireshark, then
`analyzer.py` extracts DNS, TCP, TLS and SIP statistics from the pcap files.
Each test is documented as a report in `reports/`.

## Structure

```
net-verify/
  analyzer.py        pcap parser, computes statistics
  captures/          pcap files from Wireshark (do not commit, they are large)
  reports/           test reports
    _template.md     report template
    TEST-01-dns.md
    TEST-02-tls.md
    TEST-03-sip.md
```

## Usage

1. Start a capture in Wireshark, run the test scenario, stop the capture.
2. Save it as **pcap** (not pcapng) into `captures/`.
3. `python3 analyzer.py captures/test01_dns.pcap --json reports/test01_dns.json`
4. Copy the results into the report using the template.

Requires Python 3.8+. No third-party libraries.

## Features and limitations

- Supported: pcap (libpcap), Ethernet with one VLAN tag, IPv4, TCP/UDP
- DNS: query and response counts, query types, rcode, RTT matched by (client, transaction ID)
- TCP RTT: approximate, measured from a data segment to the ACK covering it.
  Retransmissions are not handled, so the tail (p95 and above) may be misleading
- TLS: handshake records are detected by their bytes (0x16 0x03), SNI is not extracted
- SIP: plain text only, uses the `Call-ID` and `CSeq` headers.
  Compact header forms (e.g. `i:`) are recognized but lightly tested
  but it can occasionally match unrelated traffic
- The whole file is read into memory. Large captures (>500 MB) will be slow and
  memory-hungry; streaming reads are planned
- Only tested on synthetic data so far; real captures have not been processed yet
