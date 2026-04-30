'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: Luka Doljanin - ld1234
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

# ============================================================
# Parser Module - Extracts structured data from raw scapy packets
# Handles all major protocol layers: Ethernet, IPv4, IPv6, ARP,
# TCP, UDP, ICMP, ICMPv6, and DNS
# ============================================================

# Import specific protocol classes from scapy for layer detection
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, Raw, ARP, DNS, DNSQR


def parse_packet(packet):
    """
    Parse a raw scapy packet into a structured dictionary.
    Walks through each protocol layer present in the packet and
    extracts all relevant header fields into a flat dictionary.
    Also builds a 'layers' list for the GUI detail panel and
    generates a human-readable 'info' string for the packet table.
    Returns the completed dictionary with all extracted data.
    """
    # Initialize the result dictionary with default values for every field
    # Fields are grouped by protocol layer for readability
    result = {
        # --- Ethernet Layer (Layer 2) ---
        "src_mac": "N/A",       # Source MAC address
        "dst_mac": "N/A",       # Destination MAC address

        # --- Network Layer (Layer 3) ---
        "protocol": "Unknown",  # Protocol name string for display
        "src_ip": "N/A",        # Source IP address
        "dst_ip": "N/A",        # Destination IP address
        "ttl": "N/A",           # Time to Live / Hop Limit
        "ip_version": "N/A",    # IP version (4 or 6)

        # --- IP Fragmentation ---
        "frag_flags": "N/A",    # Fragmentation flags (DF, MF)
        "frag_offset": "N/A",   # Fragment offset value

        # --- Transport Layer (Layer 4) ---
        "src_port": "N/A",      # Source port number
        "dst_port": "N/A",      # Destination port number
        "tcp_flags": "N/A",     # TCP flags as readable string
        "tcp_seq": "N/A",       # TCP sequence number
        "tcp_ack": "N/A",       # TCP acknowledgment number

        # --- ICMP ---
        "icmp_type": "N/A",     # ICMP message type
        "icmp_code": "N/A",     # ICMP message code

        # --- ARP ---
        "arp_op": "N/A",        # ARP operation (Request/Reply)
        "arp_src_ip": "N/A",    # ARP sender IP
        "arp_dst_ip": "N/A",    # ARP target IP
        "arp_src_mac": "N/A",   # ARP sender MAC
        "arp_dst_mac": "N/A",   # ARP target MAC

        # --- DNS ---
        "dns_query": "N/A",     # DNS query domain name
        "dns_type": "N/A",      # DNS query or response

        # --- Payload ---
        "payload_hex": "",      # Raw payload formatted as hex string
        "payload_ascii": "",    # Raw payload formatted as ASCII string
        "length": len(packet),  # Total packet size in bytes

        # --- Display ---
        "info": "",             # Human-readable info string for the table

        # --- Layer details for the GUI detail panel ---
        "layers": [],           # List of dicts, each with 'name' and 'fields'

        # --- Raw packet reference for hex dump generation ---
        "raw_packet": packet,   # Original scapy packet object
    }

    # ---- Layer 2: Ethernet ----
    # Check if the packet has an Ethernet header and extract MAC addresses
    if packet.haslayer(Ether):
        eth = packet[Ether]
        result["src_mac"] = eth.src
        result["dst_mac"] = eth.dst
        # Add Ethernet layer details for the GUI detail tree
        result["layers"].append({
            "name": "Ethernet II",
            "fields": [
                ("Destination MAC", eth.dst),
                ("Source MAC", eth.src),
                ("EtherType", hex(eth.type)),   # Type field identifies the next layer
            ]
        })

    # ---- Layer 3: IPv4 ----
    # Extract IP header fields including addresses, TTL, and fragmentation
    if packet.haslayer(IP):
        ip = packet[IP]
        result["ip_version"] = 4
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["ttl"] = ip.ttl

        # Parse IP fragmentation flags into readable strings
        flags = []
        if ip.flags.DF:
            flags.append("DF")   # Don't Fragment flag
        if ip.flags.MF:
            flags.append("MF")   # More Fragments flag
        result["frag_flags"] = ", ".join(flags) if flags else "None"
        result["frag_offset"] = ip.frag

        # Map the IP protocol number to a human-readable name
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 58: "ICMPv6"}
        result["protocol"] = proto_map.get(ip.proto, str(ip.proto))

        # Add IPv4 layer details for the GUI detail tree
        result["layers"].append({
            "name": "Internet Protocol v4",
            "fields": [
                ("Version", ip.version),
                ("Header Length", f"{ip.ihl * 4} bytes"),    # IHL is in 32-bit words
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
    # Only checked if IPv4 was NOT present (elif)
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        result["ip_version"] = 6
        result["src_ip"] = ip6.src
        result["dst_ip"] = ip6.dst
        result["ttl"] = ip6.hlim       # IPv6 uses Hop Limit instead of TTL
        result["protocol"] = "IPv6"

        # Add IPv6 layer details for the GUI detail tree
        result["layers"].append({
            "name": "Internet Protocol v6",
            "fields": [
                ("Version", 6),
                ("Traffic Class", ip6.tc),
                ("Flow Label", ip6.fl),
                ("Payload Length", ip6.plen),
                ("Next Header", ip6.nh),     # Equivalent to IPv4 protocol field
                ("Hop Limit", ip6.hlim),
                ("Source", ip6.src),
                ("Destination", ip6.dst),
            ]
        })

    # ---- Layer 3: ARP ----
    # ARP can coexist with Ethernet so we use 'if' not 'elif'
    if packet.haslayer(ARP):
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["arp_op"] = "Request" if arp.op == 1 else "Reply"
        result["arp_src_ip"] = arp.psrc    # Protocol source (IP)
        result["arp_dst_ip"] = arp.pdst    # Protocol destination (IP)
        result["arp_src_mac"] = arp.hwsrc  # Hardware source (MAC)
        result["arp_dst_mac"] = arp.hwdst  # Hardware destination (MAC)
        # Also set the main IP fields for table display
        result["src_ip"] = arp.psrc
        result["dst_ip"] = arp.pdst

        # Generate a human-readable info string based on ARP operation
        if arp.op == 1:
            result["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            result["info"] = f"{arp.psrc} is at {arp.hwsrc}"

        # Add ARP layer details for the GUI detail tree
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
    # Extract TCP header fields including ports, sequence numbers, and flags
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["protocol"] = "TCP"
        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport
        result["tcp_seq"] = tcp.seq
        result["tcp_ack"] = tcp.ack
        # Convert TCP flags to readable format using helper function
        result["tcp_flags"] = _parse_tcp_flags(tcp.flags)

        # Build the info string showing port flow, flags, and key values
        result["info"] = (
            f"{tcp.sport} \u2192 {tcp.dport} [{result['tcp_flags']}] "
            f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
        )

        # Build the fields list for the detail panel
        fields = [
            ("Source Port", tcp.sport),
            ("Destination Port", tcp.dport),
            ("Sequence Number", tcp.seq),
            ("Acknowledgment", tcp.ack),
            ("Data Offset", f"{tcp.dataofs * 4} bytes"),  # Offset is in 32-bit words
            ("Flags", result["tcp_flags"]),
            ("Window Size", tcp.window),
            ("Checksum", hex(tcp.chksum)),
            ("Urgent Pointer", tcp.urgptr),
        ]
        # Append any TCP options (MSS, Window Scale, SACK, etc.)
        if tcp.options:
            for opt_name, opt_val in tcp.options:
                fields.append((f"Opt: {opt_name}", str(opt_val)))

        # Add TCP layer details for the GUI detail tree
        result["layers"].append({
            "name": "Transmission Control Protocol",
            "fields": fields,
        })

    # ---- Layer 4: UDP ----
    # Only checked if TCP was NOT present (elif)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        result["protocol"] = "UDP"
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport
        # UDP info shows port flow and datagram length
        result["info"] = f"{udp.sport} \u2192 {udp.dport} Len={udp.len}"

        # Add UDP layer details for the GUI detail tree
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
    # Only checked if neither TCP nor UDP were present
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        result["protocol"] = "ICMP"
        result["icmp_type"] = icmp.type
        result["icmp_code"] = icmp.code

        # Map common ICMP type codes to descriptive names
        type_names = {
            0: "Echo Reply", 3: "Dest Unreachable",
            5: "Redirect", 8: "Echo Request", 11: "Time Exceeded"
        }
        type_str = type_names.get(icmp.type, f"Type {icmp.type}")
        result["info"] = f"{type_str} (code={icmp.code})"

        # Add ICMP layer details for the GUI detail tree
        result["layers"].append({
            "name": "Internet Control Message Protocol",
            "fields": [
                ("Type", f"{type_str} ({icmp.type})"),
                ("Code", icmp.code),
                ("Checksum", hex(icmp.chksum)),
                ("ID", getattr(icmp, 'id', 'N/A')),       # Only present in echo
                ("Sequence", getattr(icmp, 'seq', 'N/A')), # Only present in echo
            ]
        })

    # ---- Layer 4: ICMPv6 ----
    elif packet.haslayer(ICMPv6EchoRequest):
        result["protocol"] = "ICMPv6"
        result["info"] = "ICMPv6 Echo Request"

    # ---- Application Layer: DNS ----
    # DNS sits on top of UDP/TCP, so we use 'if' not 'elif'
    if packet.haslayer(DNS):
        dns = packet[DNS]
        result["protocol"] = "DNS"
        # Determine if this is a query or response based on QR bit
        qr_type = "Response" if dns.qr else "Query"

        # Extract the queried domain name from the question section
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors='replace')
            result["dns_query"] = qname
            result["dns_type"] = qr_type
            result["info"] = f"DNS {qr_type}: {qname}"

        # Add DNS layer details for the GUI detail tree
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
    # Extract the application-layer payload if present
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw])
        result["payload_hex"] = _to_hex(raw_bytes)      # Hex representation
        result["payload_ascii"] = _to_ascii(raw_bytes)   # ASCII representation

    # Set a default info string if no protocol-specific one was generated
    if not result["info"]:
        result["info"] = f"{result['protocol']} {result['length']} bytes"

    return result


def _parse_tcp_flags(flags):
    """
    Convert scapy TCP flags object into a human-readable comma-separated string.
    Scapy represents flags as characters (S=SYN, A=ACK, etc.).
    This function maps each character to its full name.
    Example: 'SA' becomes 'SYN, ACK'
    """
    # Mapping of single-character flags to their full names
    flag_map = {
        "F": "FIN", "S": "SYN", "R": "RST",
        "P": "PSH", "A": "ACK", "U": "URG",
        "E": "ECE", "C": "CWR",
    }
    active = []
    flags_str = str(flags)
    # Check each known flag character against the flags string
    for char, name in flag_map.items():
        if char in flags_str:
            active.append(name)
    return ", ".join(active) if active else "None"


def _to_hex(raw_bytes):
    """
    Format raw bytes as a hex dump with 16 bytes per line.
    Each byte is shown as a two-digit hex value separated by spaces.
    Used for the payload hex section in the GUI hex panel.
    """
    hex_values = [f"{b:02x}" for b in raw_bytes]
    # Split into rows of 16 hex values each
    rows = [hex_values[i:i + 16] for i in range(0, len(hex_values), 16)]
    return "\n".join(" ".join(row) for row in rows)


def _to_ascii(raw_bytes):
    """
    Format raw bytes as ASCII text with 16 characters per line.
    Printable characters (32-126) are shown as-is.
    Non-printable bytes are replaced with dots for readability.
    Used for the payload ASCII section in the GUI hex panel.
    """
    chars = [chr(b) if 32 <= b < 127 else "." for b in raw_bytes]
    # Split into rows of 16 characters each
    rows = [chars[i:i + 16] for i in range(0, len(chars), 16)]
    return "\n".join("".join(row) for row in rows)


def format_full_hex(packet):
    """
    Generate a complete hex dump of the entire packet (all layers).
    Output format matches Wireshark style:
      offset   hex bytes (with gap at byte 8)   ASCII
      0000     48 65 6c 6c 6f 20 57 6f  72 6c 64   Hello Wor ld
    This function processes the raw bytes of every layer,
    not just the payload. Used by the GUI full hex dump section.
    """
    raw = bytes(packet)
    lines = []
    # Process 16 bytes at a time
    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]

        # Format the byte offset as 4-digit hex
        offset_str = f"{offset:04x}"

        # Format each byte as 2-digit hex, with extra space after byte 8
        hex_parts = []
        for i, byte in enumerate(chunk):
            hex_parts.append(f"{byte:02x}")
            if i == 7:
                hex_parts.append(" ")   # Visual separator between octets
        hex_str = " ".join(hex_parts)
        hex_str = hex_str.ljust(50)     # Pad to fixed width for alignment

        # Build ASCII column: printable chars shown, others replaced with dot
        ascii_str = ""
        for byte in chunk:
            if 32 <= byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str += "."

        # Combine all three columns into one line
        lines.append(f"{offset_str}   {hex_str}  {ascii_str}")

    return "\n".join(lines)