'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

# ============================================================
# Filter Module - Packet filtering engine
# Manages a set of filter criteria and applies them to packets.
# Supports filtering by protocol, source/destination IP address,
# and source/destination port number.
# ============================================================


class PacketFilter:
    """
    Manages a dictionary of active filters and provides methods
    to apply them against parsed packet dictionaries.
    All filters are AND-combined: a packet must match every
    active filter to be displayed. Empty filters are ignored.
    """

    def __init__(self):
        """
        Initialize with an empty set of filters.
        Each filter key corresponds to a field in the parsed packet dict.
        Empty string means "no filter" (match everything).
        """
        self._filters = {
            "protocol": "",    # Filter by protocol name (TCP, UDP, etc.)
            "src_ip": "",      # Filter by source IP (substring match)
            "dst_ip": "",      # Filter by destination IP (substring match)
            "src_port": "",    # Filter by source port (exact match)
            "dst_port": "",    # Filter by destination port (exact match)
        }

    def set_filter(self, key, value):
        """
        Set a specific filter field to a new value.
        Only accepts keys that exist in the filter dictionary.
        The value is stripped of whitespace to avoid matching issues.
        """
        if key in self._filters:
            self._filters[key] = str(value).strip()

    def clear_all(self):
        """
        Reset all filters to empty strings.
        After clearing, all packets will match (no filtering).
        """
        for key in self._filters:
            self._filters[key] = ""

    def get_filters(self):
        """
        Return a copy of the current filter settings.
        Returns a new dict so callers can't modify internal state.
        """
        return dict(self._filters)

    def has_active_filters(self):
        """
        Check if any filter is currently set (non-empty).
        Used by the GUI to decide whether to show filter status text.
        Returns True if at least one filter has a value.
        """
        return any(v for v in self._filters.values())

    def apply(self, packets):
        """
        Apply all active filters to a list of packets.
        Returns a new list containing only packets that match
        all filter criteria. The original list is not modified.
        """
        result = []
        for packet in packets:
            if self._matches(packet):
                result.append(packet)
        return result

    def matches(self, packet):
        """
        Public method to check if a single packet matches all filters.
        Used by the GUI polling loop to filter packets one at a time
        as they arrive from the capture thread.
        """
        return self._matches(packet)

    def _matches(self, packet):
        """
        Internal matching logic. Checks each active filter against
        the corresponding field in the packet dictionary.
        A packet must pass ALL active filters to match.
        Empty filter fields are skipped (they match everything).

        Filter types:
        - Protocol: case-insensitive exact match
        - IP addresses: substring match (allows partial IP filtering)
        - Ports: exact string match
        """
        # --- Protocol filter: case-insensitive exact match ---
        proto_filter = self._filters["protocol"]
        if proto_filter:
            if packet.get("protocol", "").upper() != proto_filter.upper():
                return False

        # --- Source IP filter: substring match ---
        # Substring allows filtering by network prefix (e.g., "192.168")
        src_ip_filter = self._filters["src_ip"]
        if src_ip_filter:
            if src_ip_filter not in str(packet.get("src_ip", "")):
                return False

        # --- Destination IP filter: substring match ---
        dst_ip_filter = self._filters["dst_ip"]
        if dst_ip_filter:
            if dst_ip_filter not in str(packet.get("dst_ip", "")):
                return False

        # --- Source port filter: exact string match ---
        src_port_filter = self._filters["src_port"]
        if src_port_filter:
            if str(packet.get("src_port", "")) != src_port_filter:
                return False

        # --- Destination port filter: exact string match ---
        dst_port_filter = self._filters["dst_port"]
        if dst_port_filter:
            if str(packet.get("dst_port", "")) != dst_port_filter:
                return False

        # Packet passed all active filters
        return True