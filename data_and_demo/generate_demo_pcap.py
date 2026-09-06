import struct
import time
import socket
import os
import random

# PCAP Global Header format:
# magic_number (4B), version_major (2B), version_minor (2B), thiszone (4B),
# sigfigs (4B), snaplen (4B), network (4B: 1 for Ethernet)
PCAP_GLOBAL_HEADER = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def make_eth_header(src_mac=b"\x00\x0c\x29\x4f\x8e\x35", dst_mac=b"\x00\x50\x56\xea\x11\x22", eth_type=0x0800):
    return dst_mac + src_mac + struct.pack("!H", eth_type)

def make_ip_header(src_ip, dst_ip, proto=socket.IPPROTO_TCP, payload_len=0, ttl=64):
    version_ihl = (4 << 4) + 5
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1000, 65000)
    flags_offset = 0x4000  # DF flag
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    hdr_without_cksum = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_len, ident, flags_offset, ttl, proto, 0, src_bytes, dst_bytes)
    cksum = checksum(hdr_without_cksum)
    return struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_len, ident, flags_offset, ttl, proto, cksum, src_bytes, dst_bytes)

def make_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq=1000, ack=0, flags=0x02, payload=b""):
    # flags: 0x02 (SYN), 0x12 (SYN-ACK), 0x10 (ACK), 0x18 (PSH-ACK), 0x04 (RST)
    data_offset = (5 << 4)
    window = 64240
    urg_ptr = 0
    pseudo_hdr = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, 20 + len(payload))
    tcp_hdr_no_cksum = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset, flags, window, 0, urg_ptr)
    tcp_cksum = checksum(pseudo_hdr + tcp_hdr_no_cksum + payload)
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset, flags, window, tcp_cksum, urg_ptr)
    ip_hdr = make_ip_header(src_ip, dst_ip, proto=socket.IPPROTO_TCP, payload_len=len(tcp_hdr) + len(payload))
    return make_eth_header() + ip_hdr + tcp_hdr + payload

def make_udp_packet(src_ip, dst_ip, src_port, dst_port, payload=b""):
    udp_len = 8 + len(payload)
    pseudo_hdr = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
    udp_hdr_no_cksum = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    udp_cksum = checksum(pseudo_hdr + udp_hdr_no_cksum + payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_cksum)
    ip_hdr = make_ip_header(src_ip, dst_ip, proto=socket.IPPROTO_UDP, payload_len=udp_len)
    return make_eth_header() + ip_hdr + udp_hdr + payload

def make_dns_query_payload(qname="google.com", qtype=1):
    # Transaction ID (2B), Flags (2B standard query 0x0100), QDCOUNT (2B = 1), ANCOUNT, NSCOUNT, ARCOUNT
    hdr = struct.pack("!HHHHHH", random.randint(100, 60000), 0x0100, 1, 0, 0, 0)
    # QNAME encoding: 3www6google3com0
    labels = b""
    for part in qname.split("."):
        labels += struct.pack("!B", len(part)) + part.encode('ascii')
    labels += b"\x00"
    qsuffix = struct.pack("!HH", qtype, 1) # Type A/TXT, Class IN
    return hdr + labels + qsuffix

def write_pcap_packet(f, raw_bytes, ts_sec, ts_usec):
    pkt_len = len(raw_bytes)
    # Packet header: ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
    pkt_hdr = struct.pack("!IIII", int(ts_sec), int(ts_usec), pkt_len, pkt_len)
    f.write(pkt_hdr + raw_bytes)

def generate_demo_pcap(filepath):
    start_time = 1788359400.0 # Base epoch
    with open(filepath, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        
        cur_ts = start_time
        
        # -------------------------------------------------------------
        # Phase 0: Benign Traffic (DNS + HTTP Browsing)
        # -------------------------------------------------------------
        dns_req = make_udp_packet("192.168.10.25", "192.168.10.1", 52100, 53, make_dns_query_payload("example.com", 1))
        write_pcap_packet(f, dns_req, cur_ts, 10000)
        cur_ts += 0.05
        
        # HTTP GET handshake + Request
        syn = make_tcp_packet("192.168.10.25", "93.184.216.34", 49152, 80, seq=100, flags=0x02)
        write_pcap_packet(f, syn, cur_ts, 20000)
        cur_ts += 0.01
        synack = make_tcp_packet("93.184.216.34", "192.168.10.25", 80, 49152, seq=5000, ack=101, flags=0x12)
        write_pcap_packet(f, synack, cur_ts, 30000)
        cur_ts += 0.01
        ack = make_tcp_packet("192.168.10.25", "93.184.216.34", 49152, 80, seq=101, ack=5001, flags=0x10)
        write_pcap_packet(f, ack, cur_ts, 40000)
        cur_ts += 0.02
        http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        http_psh = make_tcp_packet("192.168.10.25", "93.184.216.34", 49152, 80, seq=101, ack=5001, flags=0x18, payload=http_data)
        write_pcap_packet(f, http_psh, cur_ts, 50000)
        cur_ts += 1.0

        # -------------------------------------------------------------
        # Phase 1: Threat 05 - Reconnaissance / Port Scanning
        # -------------------------------------------------------------
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
        for p in scan_ports:
            scan_syn = make_tcp_packet("192.168.10.45", "192.168.10.100", 54100 + p % 100, p, seq=2000+p, flags=0x02)
            write_pcap_packet(f, scan_syn, cur_ts, 60000 + p*100)
            cur_ts += 0.01
            # Server responds with RST for closed ports
            if p not in [80, 443]:
                rst = make_tcp_packet("192.168.10.100", "192.168.10.45", p, 54100 + p % 100, seq=0, ack=2001+p, flags=0x04)
                write_pcap_packet(f, rst, cur_ts, 65000 + p*100)
            cur_ts += 0.02
        cur_ts += 2.0

        # -------------------------------------------------------------
        # Phase 2: Threat 03 - DGA Queries & DNS Tunnelling
        # -------------------------------------------------------------
        dga_domains = ["x9z8k1q4m0pl.biz", "mq991a0zplk1.biz", "k8v391lxznq.info", "w9901zqplam.biz"]
        for dom in dga_domains:
            dga_pkt = make_udp_packet("192.168.10.78", "192.168.10.1", 58312, 53, make_dns_query_payload(dom, 1))
            write_pcap_packet(f, dga_pkt, cur_ts, 11000)
            cur_ts += 0.05
        # DNS Tunneling TXT Query (Base64 encoded data)
        tunnel_pkt = make_udp_packet("192.168.10.78", "192.168.10.1", 58313, 53, make_dns_query_payload("data.chunk01.exfil-c2.net", 16)) # Type TXT = 16
        write_pcap_packet(f, tunnel_pkt, cur_ts, 15000)
        cur_ts += 2.0

        # -------------------------------------------------------------
        # Phase 3: Threat 02 - Botnet C2 Beaconing (Regular 60s Intervals)
        # -------------------------------------------------------------
        for beacon_i in range(3):
            b_syn = make_tcp_packet("192.168.10.12", "198.51.100.24", 49830 + beacon_i, 80, seq=3000, flags=0x02)
            write_pcap_packet(f, b_syn, cur_ts, 20000)
            cur_ts += 0.01
            b_post = make_tcp_packet("192.168.10.12", "198.51.100.24", 49830 + beacon_i, 80, seq=3001, ack=7001, flags=0x18, payload=b"POST /api/v1/heartbeat HTTP/1.1\r\nHost: 198.51.100.24\r\n\r\nSTATUS=IDLE")
            write_pcap_packet(f, b_post, cur_ts, 30000)
            cur_ts += 60.0 # Next periodic heartbeat

        # -------------------------------------------------------------
        # Phase 4: Threat 04 - Malware TLS Handshake (ClientHello with Legacy Ciphers)
        # -------------------------------------------------------------
        tls_hello_payload = (
            b"\x16\x03\x01\x00\x65\x01\x00\x00\x61\x03\x03" # TLS Record & Handshake (TLS 1.2)
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
            b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" # Random 32B
            b"\x00" # Session ID len 0
            b"\x00\x04\x00\x2f\x00\x35" # Ciphers: RSA_AES_128_CBC_SHA, RSA_AES_256_CBC_SHA
            b"\x01\x00" # Compression null
            b"\x00\x34" # Extension length
            b"\x00\x00\x00\x13\x00\x11\x00\x00\x0e\x72\x61\x77\x2d\x63\x32\x2d\x76\x70\x73\x2e\x6e\x65\x74" # SNI: raw-c2-vps.net
        )
        tls_pkt = make_tcp_packet("192.168.10.89", "203.0.113.88", 51234, 8443, seq=4001, ack=8001, flags=0x18, payload=tls_hello_payload)
        write_pcap_packet(f, tls_pkt, cur_ts, 40000)
        cur_ts += 2.0

        # -------------------------------------------------------------
        # Phase 5: Threat 06 - Data Exfiltration (Outbound Asymmetric Bursts)
        # -------------------------------------------------------------
        exfil_data = b"X" * 1420
        for chunk in range(50):
            exfil_pkt = make_tcp_packet("192.168.10.60", "198.51.100.99", 44102, 443, seq=10000 + chunk*1420, ack=1, flags=0x18, payload=exfil_data)
            write_pcap_packet(f, exfil_pkt, cur_ts, 50000 + chunk*100)
            cur_ts += 0.005
        cur_ts += 2.0

        # -------------------------------------------------------------
        # Phase 6: Threat 01 - Volumetric SYN Flood DDoS
        # -------------------------------------------------------------
        for flood_i in range(120):
            # Spoofed random source IPs
            spoofed_src = f"172.16.{random.randint(1,250)}.{random.randint(1,250)}"
            syn_flood = make_tcp_packet(spoofed_src, "192.168.10.100", random.randint(1024, 65530), 80, seq=random.randint(1000, 90000), flags=0x02)
            write_pcap_packet(f, syn_flood, cur_ts, random.randint(100, 90000))
            cur_ts += 0.001

    print(f"[+] Successfully generated valid multi-threat PCAP: {filepath}")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_pcap = os.path.join(script_dir, "demo_traffic.pcap")
    generate_demo_pcap(target_pcap)
