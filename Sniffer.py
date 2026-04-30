'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

# ============================================================
# Sniffer Module - Handles live packet capture and pcap file I/O
# Runs packet sniffing in a background thread so the GUI stays
# responsive during capture. Uses scapy for all capture operations.
# ============================================================

import threading
from scapy.all import sniff, rdpcap, wrpcap  # Core scapy functions
from Parser import parse_packet              # Our custom packet parser


class Sniffer:
    """
    Manages packet capture from a network interface or pcap file.
    Uses a background daemon thread for live capture so the tkinter
    main loop is never blocked. Communicates with the GUI through
    a callback function passed during initialization.
    """

    def __init__(self, packet_callback):
        """
        Initialize the sniffer with a callback function.
        The callback is called for each parsed packet and is used
        to pass packet data from the capture thread to the GUI.
        """
        self.packet_callback = packet_callback       # Function to call with each packet
        self._stop_event = threading.Event()          # Thread-safe stop signal
        self._thread = None                           # Reference to the capture thread
        self.capturing = False                        # Current capture state flag

    def start(self, interface=None):
        """
        Start live capture on the given network interface.
        Creates a daemon thread that runs scapy's sniff() function.
        Daemon threads are automatically killed when the main program exits.
        If interface is None, scapy will use the default interface.
        """
        # Don't start a second capture if one is already running
        if self.capturing:
            return
        self._stop_event.clear()     # Reset the stop signal
        self.capturing = True

        # Create and start the capture thread
        self._thread = threading.Thread(
            target=self._capture_loop,
            args=(interface,),
            daemon=True              # Thread dies when main program exits
        )
        self._thread.start()

    def stop(self):
        """
        Signal the capture thread to stop.
        Sets the threading event which the stop_filter lambda checks
        after each packet. The thread will finish after the next packet.
        """
        self._stop_event.set()
        self.capturing = False

    def _capture_loop(self, interface):
        """
        Internal capture loop that runs in the background thread.
        Uses scapy's sniff() with:
        - iface: which network interface to listen on
        - prn: callback for each captured packet
        - stop_filter: lambda checked after each packet to decide if we stop
        - store=False: don't store packets in memory (we handle storage ourselves)
        Wrapped in try/except to handle permission errors gracefully.
        """
        try:
            sniff(
                iface=interface,
                prn=self._handle_packet,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False
            )
        except Exception as e:
            # Print error to console (GUI will show capture failed via state)
            print(f"Capture error: {e}")
        finally:
            # Ensure capturing flag is cleared even if sniff() crashes
            self.capturing = False

    def _handle_packet(self, packet):
        """
        Called by scapy for each captured packet (runs in capture thread).
        Parses the raw packet using our Parser module, then forwards
        the structured result to the GUI via the callback function.
        The GUI callback puts it into a thread-safe queue.
        """
        parsed = parse_packet(packet)
        if parsed:
            self.packet_callback(parsed)

    def load_from_file(self, filepath):
        """
        Load packets from a pcap or pcapng file for offline analysis.
        Uses scapy's rdpcap() to read all packets from the file,
        then parses each one and sends it through the callback.
        Returns the count of successfully parsed packets.
        """
        packets = rdpcap(filepath)   # Read all packets from file
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
        Uses scapy's wrpcap() to write packets in standard pcap format.
        Expects a list of raw scapy packet objects (not parsed dicts).
        """
        wrpcap(filepath, packets)