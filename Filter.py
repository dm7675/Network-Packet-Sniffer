'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

class PacketFiter:
    def __init__(self):
        self._filters= {
            "protocol": "",
            "src_ip": "",
            "dst_ip": "",
            "src_port": "",
            "dst_port": "",
        }
    
    def set_filter(self, key, value):
        
        if key in self._filters:
            self._filters[key] = str(value).strip()
    
    def clear_all(sečf):
        
        for key in self._filters:
            self._filters[key]= ""
            
    def get_filters(self):
        
        return dict(self._filters)
    
    def apply(self, packets):
        result=[]
        for packet in packets:
            if self._matches(packet):
                result.append(packet)
        return result
    
    def matches (self, packet):
        return self._matches(packet)
    
    def _matches(self, packet):
        
        proto_filter= self._filter["protocol"]
        if proto_filter:
            if packet.get("protocol", "").upper() != proto_filter.upper():
                return False
        
        src_ip_filter= self._filters["src_ip"]
        if src_ip_filter:
            if src_ip_filter not in packet.get("src_ip", ""):
                return False
        
        dst_ip_filter=self._filters["dst_ip"]
        if dst_ip_filter:
            if dst_ip_filter not in packet.get("dst_ip", ""):
                return False
        
        src_port_filter= self._filter["src_port"]
        if src_port_filter:
            if str(packet.get("src_port", "")) != src_port_filter:
                return False
        
        dst_port_filter = self._filters["dst_port"]
        if dst_port_filter:
            if str(packet.get("dst_port", "")) != dst_port_filter:
                return False
        
        return True
            
        