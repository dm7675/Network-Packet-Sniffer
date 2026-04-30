'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''


import time
from collections import defaultdict


class Stats:
    """
    Tracks and computes capture statistics including total counts,
    per-protocol breakdown, byte totals, and capture rate.
    """

    def __init__(self):
        """Initialize stats by calling reset."""
        self.reset()

    def reset(self):
        """Reset all counters and timers to zero."""
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.start_time = None
        self._last_rate_time = None
        self._last_rate_count = 0
        self.packets_per_second = 0.0

    def record(self, packet):
        """
        Record a new packet into the statistics.
        Updates all counters and recalculates the capture rate.
        """
        if self.start_time is None:
            self.start_time = time.time()
            self._last_rate_time = self.start_time
            self._last_rate_count = 0

        self.total_packets += 1
        self.total_bytes += packet.get("length", 0)

        proto = packet.get("protocol", "Unknown")
        self.protocol_counts[proto] += 1

        self._update_rate()

    def _update_rate(self):
        """
        Recalculate packets per second.
        Updates every 1 second to avoid excessive computation.
        """
        now = time.time()
        elapsed = now - self._last_rate_time

        if elapsed >= 1.0:
            packets_in_interval = self.total_packets - self._last_rate_count
            self.packets_per_second = round(packets_in_interval / elapsed, 2)
            self._last_rate_time = now
            self._last_rate_count = self.total_packets

    def get_elapsed_time(self):
        """Return seconds elapsed since capture started."""
        if self.start_time is None:
            return 0
        return round(time.time() - self.start_time, 1)

    def get_elapsed_formatted(self):
        """Return elapsed time as a human-readable string."""
        elapsed = self.get_elapsed_time()
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        if minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    def get_summary(self):
        """
        Return a dictionary with all current statistics.
        Used by the GUI to update the stats display.
        """
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocol_counts": dict(self.protocol_counts),
            "packets_per_second": self.packets_per_second,
            "elapsed_seconds": self.get_elapsed_time(),
            "elapsed_formatted": self.get_elapsed_formatted(),
        }