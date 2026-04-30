'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, Raw, ARP

def parse_packet(packet):
    result= {
        #--- EThernet---
        "src_mac": "N/A",
        "dst_mac": "N/A",
        
        #--- Network layer ---
        "protocol" : "Unknown",
        "src_ip" : "N/A",
        "dst_ip": "N/A",
        "ttl": "N/A",
        "ip_version": "N/A",
        
        #--- Fragmentation ---
        "frag_flags": "N/A",
        "frag_offset": "N/A",
        
        #--- Transport layer---
        "src_port":"N/A",
        "dst_port": "N/A",
        "tcp_flags": "N/A",
        "tcp_seq": "N/A",
        "tcp_ack": "N/A",
        
        #--- ICMP ---
        "icmp_type": "N/A",
        "icmp_code": "N/A",
        
        #---ARP ---
        "arp_op": "N/A",
        "arp_src_ip": "N/A",
        "arp_dst_ip":"N/A",
        "arp_src_mac":"N/A",
        "arp_dst_mac": "N/A",
        
        #--- Payload---
        "payload_hex": "",
        "payload_ascii": "",
        "length": len(packet),
    }
    
    if packet.haslayer(Ether):
        eth = packet[Ether]
        result["src_mac"]= eth.src
        result["dst_mac"] = eth.dst
    
    if packet.haslayer(IP):
        ip= packet[IP]
        result["ip_version"]=4
        result["src_ip"]= ip.src
        result["dst_ip"]= ip.dst
        result["ttl"] = ip.ttl
        
        flags = []
        if ip.flags.DF:
            flags.append("DF")
        if ip.flags.MF:
            flags.append("MF")
        result["frag_flags"]=", ".join(flags) if flags else "None"
        result["frag_offset"]= ip.frag
        
    elif packet.haslayer(IPv6):
        ip6= packet[IPv6]
        result["ip_version"]= 6
        result["src_ip"] = ip6.src
        result ["ttl"] = ip6.hlim 
        
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["arp_op"]= "Request" if arp.op == 1 else "Reply"
        result["arp_dst_ip"] = arp.psrc
        result["arp_dst_ip"]= arp.pdst
        result["arp_src_mac"]= arp.hwsrc
        result["arp_dst_mac"]= arp.hwdst
        
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["protocol"] = "ARP"
        result["arp_op"]= "Request" if arp.op == 1 else "Reply"
        result["arp_src_ip"]= arp.psrc
        result["arp_dst_ip"]=arp.pdst
        result["arp_src_mac"]= arp.hwsrc
        result["arp_dst_mac"]= arp.hwdst
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["protocol"] = "TCP"
        result["src_port"]= tcp.sport
        result["dst_port"]= tcp.dport
        result["tcp_seq"]= tcp.seq
        result["tcp_ack"]= tcp.ack
        
        result["tcp_flags"] = _parse.tcp_flags(tcp.flags)
    
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        result["protocol"] = "UDP"
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport
        
    elif packet.haslayer(ICMP):
        result["protocol"]= "ICMP"
        result["icmp_type"]= icmp.type
        result["icmp_code"]= icmp.code
        
    elif packet.hhaslayer(ICMPv6EchoRequest):
        result["protocol"]= "ICMPv6"
        
    if packet.haslayer(Raw):
        raw_bytes= bytes(packet[Raw])
        result["payload_hex"]=_to_hex(raw_bytes)
        result["payload_ascii"]= _to_ascii(raw_bytes)
    
    return result

def _parse_tcp_flags(flags):
    
    flag_map={
        "F":"FIN",
        "S":"SYN",
        "R":"RST",
        "P":"PSH",
        "A":"ACK",
        "U":"URG",
        "E":"ECE",
        "C":"CWR",
        
    }
    active=[]
    flags_str= str(flags)
    for char, name in flag_map.item():
        if char in flags_str:
            active.append(name)
    return "-".join(active) if active else "None"

def _to_hex(raw_byte):
    
    hex_values = [f"{b:02x}" for b in raw_byte]
    rows= [hex_vallues[i:i+16] for i in range(0, len(hex_values), 16)]
    return "\n".join(" ".join(row) for row in rows)

def _to_ascii(raw_bytes):
    chars= [chr(b) if 32 <= b < 127 else "." for b in raw_bytes]
    rows= [chars[i:i+16] for i in range(0, len(chars), 16)]
    return "\n".join("".join(row) for row in rows)


    
        
        