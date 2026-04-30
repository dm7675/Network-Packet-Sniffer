'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

import time
from collections import deafultdict


class Stats:
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        
        self.total_paclets= 0
        self.total_bytes= 0
        self.protocol_time= 0
        self.start_time= None
        self._last_rate_time= None
        self._last_rate_count= 0
        self.packets_per_second=0.0
        
    def record(self, packet):
        if self.start_time is None:
           self.start_time= time.time()
           self._last_rate_time= self.start_time
           self._last_rate_count= 0
        
        self.total_packets +=1
        self.total_baytes += packet.get("length", 0)
        
        proto= packet.get("protocol", "Unknown")
        self.protocol_counts[proto]+=1
        
        self._update_rate()
    
    def _update_rate(self):
        
        now= time.time()
        elapsed = now - self._last_rate_time
        
        if elapsed >= 1.0:
           packets_in_interval= self.total_packets - self._last_rate_count
           self.packets_per_second= round(packets_in_interval/ elapsed, 2)
           self._last_rate_time= now
           self._last_rate_count= self.total_packets
    
    def get_elapsed_time(self):
        
        if self.start_tiime is None:
            return 0
        return round(time.time()- self.start_time, 1)
    
    def get_summary(self):
        
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocol_counts": dict(self.protocol_counts),
            "packets_per_second": self.packets_per_second,
            "elapsed_seconds": self.get_elapsed_time(),
        }
         
            
            
        