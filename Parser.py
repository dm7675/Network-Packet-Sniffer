'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: Luka Doljanin - ld1234
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''


from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, Raw, ARP, DNS, DNSQR


def parse_packet(packet):
    """
    Parse a raw scapy packet into a structured dictionary.
    Extracts fields from each protocol layer present in the packet.
    Returns a dict with all relevant header fields and payload data.
    """
    result = {
        # --- Ethernet Layer ---
        "src_mac": "N/A",
        "dst_mac": "N/A",

        # --- Network Layer ---
        "protocol": "Unknown",
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "ttl": "N/A",
        "ip_version": "N/A",

        # --- IP Fragmentation ---
        "frag_flags": "N/A",
        "frag_offset": "N/A",

        # --- Transport Layer ---
        "src_port": "N/A",
        "dst_port": "N/A",
        "tcp_flags": "N/A",
        "tcp_seq": "N/A",
        "tcp_ack": "N/A",

        # --- ICMP ---
        "icmp_type": "N/A",
        "icmp_code": "N/A",

        # --- ARP ---
        "arp_op": "N/A",
        "arp_src_ip": "N/A",
        "arp_dst_ip": "N/A",
        "arp_src_mac": "N/A",
        "arp_dst_mac": "N/A",

        # --- DNS ---
        "dns_query": "N/A",
        "dns_type": "N/A",

        # --- Payload ---
        "payload_hex": "",
        "payload_ascii": "",
        "length": len(packet),

        # --- Info string for display ---
        "info": "",

        # --- Layer detail list for detail panel ---
        "layers": [],

        # --- Raw packet reference for hex dump ---
        "raw_packet": packet,
    }

    # ---- Layer 2: Ethernet ----
    if packet.haslayer(Ether):
        eth = packet[Ether]
        result["src_mac"] = eth.src
        result["dst_mac"] = eth.dst
        result["layers"].append({
            "name": "Ethernet II",
            "fields": [
                ("Destination MAC", eth.dst),
                ("Source MAC", eth.src),
                ("EtherType", hex(eth.type)),
            ]
        })

    # ---- Layer 3: IPv4 ----
    if packet.haslayer(IP):
        ip = packet[IP]
        result["ip_version"] = 4
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["ttl"] = ip.ttl

        # Parse IP fragmentation flags
        flags = []
        if ip.flags.DF:
            flags.append("DF")
        if ip.flags.MF:
            flags.append("MF")
        result["frag_flags"] = ", ".join(flags) if flags else "None"
        result["frag_offset"] = ip.frag

        # Map IP protocol number to name
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 58: "ICMPv6"}
        result["protocol"] = proto_map.get(ip.proto, str(ip.proto))

        result["layers"].append({
            "name": "Internet Protocol v4",
            "fields": [
                ("Version", ip.version),
                ("Header Length", f"{ip.ihl * 4} bytes"),
                ("DSCP/ToS", hex(ip.tos)),
                ("Total Length", ip.len),
                ("Identification", hex(ip.id)),
                ("Flags", result["frag_flags"]),
                ("Fragment Offset", ip.frag),
                ("TTL", ip.ttl),
                ("Protocol", f"{result['protocol']} ({ip.proto})"),
                ("Checksum", hex(ip.chksum)),
                ("Source", ip.src),
                ("Destination", ip.dst),
            ]
        })

    # ---- Layer 3: IPv6 ----
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        result["ip_version"] = 6
        result["src_ip"] = ip6.src
        result["dst_ip"] = ip6.dst
        result["ttl"] = ip6.hlim
        result["protocol"] = "IPv6"

        result["layers"].append({
            "name": "Internet Protocol v6",
            "fields": [
                ("Version", 6),
                ("Traffic Class", ip6.tc),
                ("Flow Label", ip6.fl),
                ("Payload Length", ip6.plen),
                ("Next Header", ip6.nh),
                ("Hop Limit", ip6.hlim),
                ("Source", ip6.src),
                ("Destination", ip6.dst),
            ]
        })

    # ---- Layer 3: ARP ----
    if packet.haslayer(ARP):
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["arp_op"] = "Request" if arp.op == 1 else "Reply"
        result["arp_src_ip"] = arp.psrc
        result["arp_dst_ip"] = arp.pdst
        result["arp_src_mac"] = arp.hwsrc
        result["arp_dst_mac"] = arp.hwdst
        result["src_ip"] = arp.psrc
        result["dst_ip"] = arp.pdst

        if arp.op == 1:
            result["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            result["info"] = f"{arp.psrc} is at {arp.hwsrc}"

        result["layers"].append({
            "name": "Address Resolution Protocol",
            "fields": [
                ("Hardware Type", arp.hwtype),
                ("Protocol Type", hex(arp.ptype)),
                ("Hw Size", arp.hwlen),
                ("Proto Size", arp.plen),
                ("Opcode", f"{result['arp_op']} ({arp.op})"),
                ("Sender MAC", arp.hwsrc),
                ("Sender IP", arp.psrc),
                ("Target MAC", arp.hwdst),
                ("Target IP", arp.pdst),
            ]
        })

    # ---- Layer 4: TCP ----
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["protocol"] = "TCP"
        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport
        result["tcp_seq"] = tcp.seq
        result["tcp_ack"] = tcp.ack
        result["tcp_flags"] = _parse_tcp_flags(tcp.flags)

        result["info"] = (
            f"{tcp.sport} \u2192 {tcp.dport} [{result['tcp_flags']}] "
            f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
        )

        fields = [
            ("Source Port", tcp.sport),
            ("Destination Port", tcp.dport),
            ("Sequence Number", tcp.seq),
            ("Acknowledgment", tcp.ack),
            ("Data Offset", f"{tcp.dataofs * 4} bytes"),
            ("Flags", result["tcp_flags"]),
            ("Window Size", tcp.window),
            ("Checksum", hex(tcp.chksum)),
            ("Urgent Pointer", tcp.urgptr),
        ]
        # Add TCP options if present
        if tcp.options:
            for opt_name, opt_val in tcp.options:
                fields.append((f"Opt: {opt_name}", str(opt_val)))

        result["layers"].append({
            "name": "Transmission Control Protocol",
            "fields": fields,
        })

    # ---- Layer 4: UDP ----
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        result["protocol"] = "UDP"
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport
        result["info"] = f"{udp.sport} \u2192 {udp.dport} Len={udp.len}"

        result["layers"].append({
            "name": "User Datagram Protocol",
            "fields": [
                ("Source Port", udp.sport),
                ("Destination Port", udp.dport),
                ("Length", udp.len),
                ("Checksum", hex(udp.chksum)),
            ]
        })

    # ---- Layer 4: ICMP ----
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        result["protocol"] = "ICMP"
        result["icmp_type"] = icmp.type
        result["icmp_code"] = icmp.code

        type_names = {
            0: "Echo Reply", 3: "Dest Unreachable",
            5: "Redirect", 8: "Echo Request", 11: "Time Exceeded"
        }
        type_str = type_names.get(icmp.type, f"Type {icmp.type}")
        result["info"] = f"{type_str} (code={icmp.code})"

        result["layers"].append({
            "name": "Internet Control Message Protocol",
            "fields": [
                ("Type", f"{type_str} ({icmp.type})"),
                ("Code", icmp.code),
                ("Checksum", hex(icmp.chksum)),
                ("ID", getattr(icmp, 'id', 'N/A')),
                ("Sequence", getattr(icmp, 'seq', 'N/A')),
            ]
        })

    # ---- Layer 4: ICMPv6 ----
    elif packet.haslayer(ICMPv6EchoRequest):
        result["protocol"] = "ICMPv6"
        result["info"] = "ICMPv6 Echo Request"

    # ---- Application Layer: DNS ----
    if packet.haslayer(DNS):
        dns = packet[DNS]
        result["protocol"] = "DNS"
        qr_type = "Response" if dns.qr else "Query"

        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors='replace')
            result["dns_query"] = qname
            result["dns_type"] = qr_type
            result["info"] = f"DNS {qr_type}: {qname}"

        result["layers"].append({
            "name": "Domain Name System",
            "fields": [
                ("Transaction ID", hex(dns.id)),
                ("Type", qr_type),
                ("Questions", dns.qdcount),
                ("Answers", dns.ancount),
                ("Query", result.get("dns_query", "N/A")),
            ]
        })

    # ---- Payload / Raw Data ----
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw])
        result["payload_hex"] = _to_hex(raw_bytes)
        result["payload_ascii"] = _to_ascii(raw_bytes)

    # Set default info string if none was generated
    if not result["info"]:
        result["info"] = f"{result['protocol']} {result['length']} bytes"

    return result


def _parse_tcp_flags(flags):
    """
    Convert scapy TCP flags object into human-readable string.
    Returns something like 'SYN, ACK' instead of 'SA'.
    """
    flag_map = {
        "F": "FIN", "S": "SYN", "R": "RST",
        "P": "PSH", "A": "ACK", "U": "URG",
        "E": "ECE", "C": "CWR",
    }
    active = []
    flags_str = str(flags)
    for char, name in flag_map.items():
        if char in flags_str:
            active.append(name)
    return ", ".join(active) if active else "None"


def _to_hex(raw_bytes):
    """
    Format raw bytes as hex dump lines (16 bytes per line).
    Returns multi-line string with hex values.
    """
    hex_values = [f"{b:02x}" for b in raw_bytes]
    rows = [hex_values[i:i + 16] for i in range(0, len(hex_values), 16)]
    return "\n".join(" ".join(row) for row in rows)


def _to_ascii(raw_bytes):
    """
    Format raw bytes as ASCII representation.
    Non-printable characters replaced with dots.
    """
    chars = [chr(b) if 32 <= b < 127 else "." for b in raw_bytes]
    rows = [chars[i:i + 16] for i in range(0, len(chars), 16)]
    return "\n".join("".join(row) for row in rows)


def format_full_hex(packet):
    """
    Generate a full hex dump of the entire packet (all layers).
    Shows offset, hex bytes, and ASCII side by side.
    Used by the GUI hex dump panel.
    """
    raw = bytes(packet)
    lines = []
    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]

        # Hex offset
        offset_str = f"{offset:04x}"

        # Hex bytes with space separator at byte 8
        hex_parts = []
        for i, byte in enumerate(chunk):
            hex_parts.append(f"{byte:02x}")
            if i == 7:
                hex_parts.append(" ")
        hex_str = " ".join(hex_parts)
        hex_str = hex_str.ljust(50)

        # ASCII representation
        ascii_str = ""
        for byte in chunk:
            if 32 <= byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str += "."

        lines.append(f"{offset_str}   {hex_str}  {ascii_str}")

    return "\n".join(lines)