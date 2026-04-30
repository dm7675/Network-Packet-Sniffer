'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: David Markovic - dm7675
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''




class PacketFilter:
    """
    Manages a set of active filters and applies them to packets.
    Supports filtering by protocol, source/destination IP, and ports.
    """

    def __init__(self):
        """Initialize with empty filter values."""
        self._filters = {
            "protocol": "",
            "src_ip": "",
            "dst_ip": "",
            "src_port": "",
            "dst_port": "", 
        }

    def set_filter(self, key, value):
        """
        Set a specific filter field to a value.
        Only accepts known filter keys.
        """
        if key in self._filters:
            self._filters[key] = str(value).strip()

    def clear_all(self):
        """Reset all filters to empty strings."""
        for key in self._filters:
            self._filters[key] = ""

    def get_filters(self):
        """Return a copy of the current filter settings."""
        return dict(self._filters)

    def has_active_filters(self):
        """Check if any filter is currently set."""
        return any(v for v in self._filters.values())

    def apply(self, packets):
        """
        Filter a list of packets. Returns only those matching
        all active filter criteria.
        """
        result = []
        for packet in packets:
            if self._matches(packet):
                result.append(packet)
        return result

    def matches(self, packet):
        """Public method to check if a single packet matches filters."""
        return self._matches(packet)

    def _matches(self, packet):
        """
        Internal matching logic. A packet must pass ALL active filters.
        Empty filter fields are skipped (match everything).
        """
        # Protocol filter - case insensitive exact match
        proto_filter = self._filters["protocol"]
        if proto_filter:
            if packet.get("protocol", "").upper() != proto_filter.upper():
                return False

        # Source IP filter - substring match
        src_ip_filter = self._filters["src_ip"]
        if src_ip_filter:
            if src_ip_filter not in str(packet.get("src_ip", "")):
                return False

        # Destination IP filter - substring match
        dst_ip_filter = self._filters["dst_ip"]
        if dst_ip_filter:
            if dst_ip_filter not in str(packet.get("dst_ip", "")):
                return False

        # Source port filter - exact match
        src_port_filter = self._filters["src_port"]
        if src_port_filter:
            if str(packet.get("src_port", "")) != src_port_filter:
                return False

        # Destination port filter - exact match
        dst_port_filter = self._filters["dst_port"]
        if dst_port_filter:
            if str(packet.get("dst_port", "")) != dst_port_filter:
                return False

        return True