import os

# Get directory where this script is located (data_and_demo)
script_dir = os.path.dirname(os.path.abspath(__file__))
out_dir = os.path.join(script_dir, "zeek_logs")
os.makedirs(out_dir, exist_ok=True)

# 1. conn.log (L3/L4 connections: DDoS, Recon, Exfil, Beaconing)
conn_log_content = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-09-02-14-30-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]
1788359400.120000\tC101\t192.168.10.45\t54120\t192.168.10.100\t80\ttcp\thttp\t0.002100\t0\t0\tREJ\t-\t-\t0\tSr\t1\t44\t1\t40\t-
1788359400.125000\tC102\t192.168.10.45\t54121\t192.168.10.100\t22\ttcp\tssh\t0.001900\t0\t0\tREJ\t-\t-\t0\tSr\t1\t44\t1\t40\t-
1788359400.130000\tC103\t192.168.10.45\t54122\t192.168.10.100\t443\ttcp\tssl\t0.003500\t0\t0\tREJ\t-\t-\t0\tSr\t1\t44\t1\t40\t-
1788359418.440000\tC104\t192.168.10.78\t58312\t192.168.10.1\t53\tudp\tdns\t0.012000\t68\t124\tSF\t-\t-\t0\tDd\t1\t96\t1\t152\t-
1788359432.810000\tC105\t192.168.10.12\t49830\t198.51.100.24\t443\ttcp\tssl\t0.450000\t382\t1420\tSF\t-\t-\t0\tShADadFf\t6\t650\t8\t1820\t-
1788359492.890000\tC106\t192.168.10.12\t49831\t198.51.100.24\t443\ttcp\tssl\t0.460000\t382\t1420\tSF\t-\t-\t0\tShADadFf\t6\t650\t8\t1820\t-
1788359502.150000\tC107\t192.168.10.60\t44102\t198.51.100.99\t443\ttcp\tssl\t28.450000\t260571136\t312450\tSF\t-\t-\t0\tShADadFf\t178400\t267707136\t4120\t328930\t-
1788359520.670000\tC108\t192.168.10.201\t61200\t192.168.10.100\t80\ttcp\thttp\t0.000100\t0\t0\tS0\t-\t-\t0\tS\t1\t40\t0\t0\t-
#close\t2026-09-02-14-35-00
"""

# 2. dns.log (DNS queries: DGA & Tunnelling)
dns_log_content = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdns
#open\t2026-09-02-14-30-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass_name\tqtype_name\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tstring\tstring\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool
1788359418.440000\tC104\t192.168.10.78\t58312\t192.168.10.1\t53\tudp\t4219\t0.012000\tx9z8k1q4m0pl.biz\tC_INTERNET\tA\tNXDOMAIN\tF\tF\tT\tT\t0\t-\t-\tF
1788359419.120000\tC109\t192.168.10.78\t58313\t192.168.10.1\t53\tudp\t4220\t0.011000\tmq991a0zplk1.biz\tC_INTERNET\tA\tNXDOMAIN\tF\tF\tT\tT\t0\t-\t-\tF
1788359420.050000\tC110\t192.168.10.78\t58314\t192.168.10.1\t53\tudp\t4221\t0.015000\tdata.chunk01.exfil-c2.net\tC_INTERNET\tTXT\tNOERROR\tT\tF\tT\tT\t0\t"OK_ACK_01"\t60.0\tF
#close\t2026-09-02-14-35-00
"""

# 3. ssl.log (Encrypted TLS/QUIC Metadata)
ssl_log_content = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tssl
#open\t2026-09-02-14-30-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tresumed\tlast_alert\tnext_protocol\testablished\tja3\tja3s\tja4
#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tstring\tbool\tstring\tstring\tbool\tstring\tstring\tstring
1788359432.810000\tC105\t192.168.10.12\t49830\t198.51.100.24\t443\tTLSv13\tTLS_AES_128_GCM_SHA256\tx25519\ttelemetry.c2-listener.org\tF\t-\th2\tT\t6734f37431670b3ab4292b8f60f29984\tec74a5c5110605f9f8eac30b50377403\tt13d1516h2_8daaf6152771_e562703ab853
1788359445.920000\tC111\t192.168.10.89\t51234\t203.0.113.88\t8443\tTLSv12\tTLS_RSA_WITH_AES_128_CBC_SHA\tsecp256r1\traw-c2-vps.net\tF\t-\t-\tT\tde350869b8c85de67a350c8d186f11e6\t4982a5c5110605f9f8eac30b50377403\tt12d090400_b38743105781_a48910ab3812
#close\t2026-09-02-14-35-00
"""

# 4. http.log (HTTP requests/responses)
http_log_content = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\thttp
#open\t2026-09-02-14-30-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\ttrans_depth\tmethod\thost\turi\treferrer\tversion\tuser_agent\trequest_body_len\tresponse_body_len\tstatus_code\tstatus_msg
#types\ttime\tstring\taddr\tport\taddr\tport\tcount\tstring\tstring\tstring\tstring\tstring\tstring\tcount\tcount\tcount\tstring
1788359432.810000\tC105\t192.168.10.12\t49830\t198.51.100.24\t80\t1\tPOST\t198.51.100.24\t/api/v1/heartbeat\t-\t1.1\tMozilla/5.0 (Windows NT 10.0; Win64; x64)\t128\t64\t200\tOK
1788359492.890000\tC106\t192.168.10.12\t49831\t198.51.100.24\t80\t1\tPOST\t198.51.100.24\t/api/v1/heartbeat\t-\t1.1\tMozilla/5.0 (Windows NT 10.0; Win64; x64)\t128\t64\t200\tOK
#close\t2026-09-02-14-35-00
"""

# Write files
files = {
    "conn.log": conn_log_content,
    "dns.log": dns_log_content,
    "ssl.log": ssl_log_content,
    "http.log": http_log_content,
}

for filename, content in files.items():
    filepath = os.path.join(out_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")
    print(f"[+] Created {filepath}")

print(f"\nAll Zeek log files successfully generated in {out_dir}")