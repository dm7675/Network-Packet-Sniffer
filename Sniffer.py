'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

import threading
from scapy.all import sniff, rdpcap
from parser import parse_packet


class Sniffer:
    

 def __init__(self, packet_callback):
    self.packet_callback = packet_callback
    self._stop_event= threading.Event()
    self._thread= None
    self.capturing= False

 def start(self, interface=None):
     if self._stop_event.is_set():
         return
     self._stop_event.clear()
     self.capturing= True
     
     self._thread= threading.Thread(
         target=self._capture_loop,
         args=(interface,),
         deamon=True
     )
     self._thread.start()
 
 def stop(self):
     self._stop_event.set()
     self.capruring= False
     
 def _capture_loop(self, interface):
     sniff(
         iface= interface,
         prn=self._handle_packet,
         stop_filter=lambda p: self._stop_event.is_set(),
         store=False
     )
 def _handle_packet(self, packet):
     parsed = parse_packet(packet)
     if parsed:
         self.packet_callback(parsed)
         
 def load_from_file(self, filepath):
     
     packet= rdpcap(filepath)
     count=0
     for packet in packets:
         parsed = parse_packet(packet)
         if parsed:
             self.packet_callback(parsed)
             count += 1
     return count
     
     