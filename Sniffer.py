'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''



import threading
from scapy.all import sniff, rdpcap, wrpcap
from Parser import parse_packet


class Sniffer:
    """
    Manages packet capture from a network interface or pcap file.
    Uses a background thread to keep the GUI responsive during capture.
    """

    def __init__(self, packet_callback):
        """
        Initialize the sniffer with a callback function.
        The callback receives each parsed packet dict.
        """
        self.packet_callback = packet_callback
        self._stop_event = threading.Event()
        self._thread = None
        self.capturing = False

    def start(self, interface=None):
        """
        Start live capture on the given network interface.
        Launches a daemon thread so the main thread stays free.
        """
        if self.capturing:
            return
        self._stop_event.clear()
        self.capturing = True

        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface,),
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Signal the capture thread to stop."""
        self._stop_event.set()
        self.capturing = False

    def _capture_loop(self, interface):
        """
        Internal capture loop running in background thread.
        Uses scapy sniff with a stop filter that checks the event.
        """
        try:
            sniff(
                iface=interface,
                prn=self._handle_packet,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False
            )
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.capturing = False

    def _handle_packet(self, packet):
        """
        Process each captured packet through the parser
        and forward the result to the GUI callback.
        """
        parsed = parse_packet(packet)
        if parsed:
            self.packet_callback(parsed)

    def load_from_file(self, filepath):
        """
        Load packets from a pcap/pcapng file for offline analysis.
        Returns the number of packets successfully parsed.
        """
        packets = rdpcap(filepath)
        count = 0
        for packet in packets:
            parsed = parse_packet(packet)
            if parsed:
                self.packet_callback(parsed)
                count += 1
        return count

    @staticmethod
    def save_to_file(filepath, packets):
        """
        Save raw packet objects to a pcap file.
        Expects a list of raw scapy packet objects.
        """
        wrpcap(filepath, packets)