'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

# ============================================================
# Stats Module - Real-time capture statistics tracker
# Counts total packets, bytes, per-protocol distribution,
# calculates capture rate, and tracks elapsed time.
# ============================================================

import time
from collections import defaultdict  # Auto-initializing dictionary for counters


class Stats:
    """
    Tracks and computes capture statistics in real time.
    Updated by the GUI each time a new packet arrives.
    The GUI polls get_summary() every second to refresh the display.
    """

    def __init__(self):
        """Initialize all statistics by calling reset."""
        self.reset()

    def reset(self):
        """
        Reset all counters and timers to their initial zero state.
        Called at startup and when the user clears all packets.
        """
        self.total_packets = 0                      # Running count of all packets
        self.total_bytes = 0                         # Running total of all bytes
        self.protocol_counts = defaultdict(int)      # Dict mapping protocol name to count
        self.start_time = None                       # Timestamp of first packet
        self._last_rate_time = None                  # Last time we calculated the rate
        self._last_rate_count = 0                    # Packet count at last rate calculation
        self.packets_per_second = 0.0                # Current capture rate

    def record(self, packet):
        """
        Record a new packet into the statistics.
        Called once for each packet received by the GUI.
        Updates total counts, per-protocol count, and triggers
        a rate recalculation if enough time has passed.
        """
        # Initialize timing on the very first packet
        if self.start_time is None:
            self.start_time = time.time()
            self._last_rate_time = self.start_time
            self._last_rate_count = 0

        # Increment counters
        self.total_packets += 1
        self.total_bytes += packet.get("length", 0)

        # Increment the count for this packet's protocol
        proto = packet.get("protocol", "Unknown")
        self.protocol_counts[proto] += 1

        # Recalculate capture rate if interval has elapsed
        self._update_rate()

    def _update_rate(self):
        """
        Recalculate the packets-per-second capture rate.
        Only updates every 1 second to avoid excessive computation
        and to provide a stable, readable rate value.
        Uses a sliding window: (packets since last check) / (time since last check)
        """
        now = time.time()
        elapsed = now - self._last_rate_time

        if elapsed >= 1.0:
            # Calculate packets captured in this interval
            packets_in_interval = self.total_packets - self._last_rate_count
            self.packets_per_second = round(packets_in_interval / elapsed, 2)
            # Reset the interval tracking
            self._last_rate_time = now
            self._last_rate_count = self.total_packets

    def get_elapsed_time(self):
        """
        Return the number of seconds elapsed since the first packet.
        Returns 0 if no packets have been recorded yet.
        """
        if self.start_time is None:
            return 0
        return round(time.time() - self.start_time, 1)

    def get_elapsed_formatted(self):
        """
        Return elapsed time as a human-readable string.
        Shows minutes and seconds (e.g., '2m 34s') or just seconds
        if under one minute (e.g., '45s').
        """
        elapsed = self.get_elapsed_time()
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        if minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    def get_summary(self):
        """
        Return a dictionary with all current statistics.
        Called by the GUI every second to refresh the stats panel.
        Returns a snapshot of all tracked values in a single dict.
        """
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocol_counts": dict(self.protocol_counts),  # Convert defaultdict to regular dict
            "packets_per_second": self.packets_per_second,
            "elapsed_seconds": self.get_elapsed_time(),
            "elapsed_formatted": self.get_elapsed_formatted(),
        }