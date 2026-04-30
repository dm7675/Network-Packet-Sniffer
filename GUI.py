'''
@ASSESSME.USERID: Wrong way
@ASSESSME.AUTHOR: Luka Doljanin - ld1234
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''

# ============================================================
# GUI Module - Main graphical interface for the packet sniffer
# Built with Tkinter using a dark theme inspired by Wireshark
# ============================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import queue
import time

# Import our custom modules for backend functionality
from Sniffer import Sniffer          # Handles live capture and file loading
from Filter import PacketFilter      # Manages packet filtering logic
from Stats import Stats              # Tracks capture statistics
from Parser import format_full_hex   # Formats raw bytes as hex dump


# ============================================================
# Protocol color mapping for the packet table rows
# Each protocol gets a distinct background/foreground combo
# so users can visually identify traffic types at a glance
# ============================================================
PROTO_TAGS = {
    "TCP":    {"background": "#0d2f4a", "foreground": "#7db9e8"},
    "UDP":    {"background": "#0d3318", "foreground": "#7ec87e"},
    "ICMP":   {"background": "#302c00", "foreground": "#e0cc66"},
    "ICMPv6": {"background": "#302c00", "foreground": "#e0cc66"},
    "DNS":    {"background": "#25123a", "foreground": "#c07ee8"},
    "ARP":    {"background": "#331a00", "foreground": "#e8a07e"},
    "IPv6":   {"background": "#002233", "foreground": "#66c8e8"},
}

# ============================================================
# Color palette dictionary for the dark theme
# Used throughout the GUI for consistent styling
# ============================================================
C = {
    "bg":      "#171614",   # Main background color
    "surface": "#1c1b19",   # Slightly lighter surface for panels
    "surface2":"#222120",   # Secondary surface for inputs/buttons
    "border":  "#333230",   # Border and separator color
    "text":    "#cdccca",   # Primary text color
    "muted":   "#797876",   # Secondary/dimmed text color
    "faint":   "#4a4948",   # Very dim text for disabled states
    "accent":  "#4f98a3",   # Primary accent color (teal)
    "accent2": "#3a7a85",   # Darker accent for buttons
    "red":     "#a13544",   # Red for stop button and errors
    "sel":     "#1a3a5c",   # Selection highlight color
    "hex_bg":  "#141312",   # Hex dump panel background
    "hex_fg":  "#b5cea8",   # Hex dump text color (green tint)
}


def fmt_time():
    """
    Generate a formatted timestamp string for the current moment.
    Returns format like '14:32:05.123' with millisecond precision.
    Used to timestamp each captured packet in the table.
    """
    t = time.time()
    ms = int((t % 1) * 1000)
    return time.strftime("%H:%M:%S") + f".{ms:03d}"


def fmt_bytes(num_bytes):
    """
    Convert a byte count into a human-readable string.
    Automatically selects B, KB, or MB unit based on size.
    Used in the statistics panel to show total traffic volume.
    """
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 ** 2:
        return f"{num_bytes / 1024:.1f} KB"
    else:
        return f"{num_bytes / 1024 ** 2:.1f} MB"


def vertical_separator(parent):
    """
    Insert a thin vertical separator line into a toolbar.
    Provides visual grouping between toolbar button sections.
    """
    ttk.Separator(parent, orient="vertical").pack(
        side="left",
        fill="y",
        padx=10,
        pady=3
    )


# ============================================================
# Main GUI Application Class
# ============================================================
class PacketSnifferGUI:
    """
    The main application class that builds and manages the entire
    graphical interface. Connects to the Sniffer, Filter, and Stats
    modules to provide a complete packet analysis experience.

    Layout structure:
    ┌─────────────────────────────────────────────┐
    │ Toolbar (interface selector, start/stop)     │
    │ Filter Bar (protocol, IP, port filters)      │
    ├─────────────────────────────────────────────┤
    │ Packet Table (scrollable list of packets)    │
    ├────────────────────────┬────────────────────┤
    │ Detail/Hex Tabs        │ Statistics Panel    │
    └────────────────────────┴────────────────────┘
    """

    def __init__(self, root):
        """
        Initialize the GUI application.
        Sets up all state variables, builds the UI, and starts
        the background polling loop for incoming packets.
        """
        self.root = root
        self.root.title("NetSniffer-Packet Analyzer")
        self.root.geometry("1440x860")
        self.root.minsize(1000, 640)
        self.root.configure(bg=C["bg"])

        # Initialize backend components
        self._filter = PacketFilter()                    # Filter engine instance
        self._stats = Stats()                            # Statistics tracker
        self._sniffer = Sniffer(self._on_packet_received)  # Capture engine with callback

        # Thread-safe queue for passing packets from capture thread to GUI
        self._packet_queue = queue.Queue()

        # Packet storage
        self._all_packets = []              # Master list of all parsed packet dicts
        self._packet_times = []             # Parallel list of formatted timestamps
        self._visible_packet_indexes = []   # Indexes of packets passing the filter

        # State tracking
        self._packet_counter = 0    # Sequential packet number counter
        self._capturing = False     # Whether live capture is currently active
        self._autoscroll = tk.BooleanVar(value=True)  # Auto-scroll toggle

        # Build all GUI components in order
        self._build_styles()     # Configure the dark ttk theme
        self._build_toolbar()    # Top bar with controls
        self._build_filter_bar() # Filter input row

        # Horizontal separator between toolbar and main content
        ttk.Separator(self.root, orient="horizontal").pack(fill="x")

        self._build_body()          # Main content area (table + details + stats)
        self._poll_queue()          # Start the packet polling loop (runs every 100ms)
        self._update_stats_panel()  # Start the stats refresh loop (runs every 1s)

    # ============================================================
    # Style Configuration - Dark Theme Setup
    # ============================================================
    def _build_styles(self):
        """
        Configure ttk styles for the entire application.
        Sets up the dark color scheme for all widget types including
        frames, buttons, entries, treeviews, notebooks, and scrollbars.
        Uses the 'clam' theme as base since it supports the most customization.
        """
        style = ttk.Style(self.root)
        style.theme_use("clam")

        # Global defaults applied to all ttk widgets
        style.configure(
            ".",
            background=C["bg"],
            foreground=C["text"],
            fieldbackground=C["surface2"],
            bordercolor=C["border"],
            troughcolor=C["surface"],
            font=("Segoe UI", 10),
        )

        # Individual widget type overrides
        style.configure("TFrame", background=C["bg"])
        style.configure("TLabel", background=C["bg"], foreground=C["text"])
        style.configure("TSeparator", background=C["border"])
        style.configure("TPanewindow", background=C["bg"])

        # Standard button style (gray)
        style.configure(
            "TButton",
            background=C["surface2"],
            foreground=C["text"],
            bordercolor=C["border"],
            padding=(10, 5),
            relief="flat",
        )
        style.map(
            "TButton",
            background=[
                ("active", C["border"]),     # Hover state
                ("pressed", C["bg"]),        # Click state
            ],
        )

        # Start button style (teal/accent colored)
        style.configure(
            "Start.TButton",
            background=C["accent2"],
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Start.TButton",
            background=[
                ("active", C["accent"]),     # Brighter on hover
                ("disabled", C["faint"]),     # Dimmed when disabled
            ],
        )

        # Stop button style (red)
        style.configure(
            "Stop.TButton",
            background=C["red"],
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Stop.TButton",
            background=[
                ("active", "#c04050"),       # Brighter red on hover
                ("disabled", C["faint"]),
            ],
        )

        # Text entry fields
        style.configure(
            "TEntry",
            fieldbackground=C["surface2"],
            foreground=C["text"],
            bordercolor=C["border"],
            insertcolor=C["text"],           # Cursor color
        )

        # Dropdown combobox
        style.configure(
            "TCombobox",
            fieldbackground=C["surface2"],
            foreground=C["text"],
            bordercolor=C["border"],
            insertcolor=C["muted"],
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", C["surface2"])],
            selectbackground=[("readonly", C["surface2"])],
        )

        # Treeview (used for packet table and detail panel)
        style.configure(
            "Treeview",
            background=C["surface"],
            foreground=C["text"],
            fieldbackground=C["surface"],
            bordercolor=C["border"],
            rowheight=23,                    # Compact row height
        )
        style.map(
            "Treeview",
            background=[("selected", C["sel"])],     # Blue highlight on select
            foreground=[("selected", "#ffffff")],
        )

        # Notebook tabs (for Details / Hex tabs)
        style.configure("TNotebook", background=C["bg"], bordercolor=C["border"])
        style.configure(
            "TNotebook.Tab",
            background=C["surface"],
            foreground=C["muted"],
            padding=(14, 5),
        )
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", C["bg"]),       # Active tab matches background
                ("active", C["surface2"]),   # Hover state
            ],
            foreground=[
                ("selected", C["accent"]),   # Active tab text is accent color
                ("active", C["text"]),
            ],
        )

        # Label frames (used for statistics panel border)
        style.configure("TLabelframe", background=C["bg"], bordercolor=C["border"])
        style.configure(
            "TLabelframe.Label",
            background=C["bg"],
            foreground=C["accent"],
            font=("Segoe UI", 9, "bold"),
        )

        # Checkbox (auto-scroll toggle)
        style.configure(
            "TCheckbutton",
            background=C["bg"],
            foreground=C["muted"],
            focuscolor=C["accent"],
        )

        # Scrollbar styling
        style.configure(
            "TScrollbar",
            background=C["surface2"],
            troughcolor=C["surface"],
            bordercolor=C["border"],
            arrowcolor=C["muted"],
        )

    # ============================================================
    # Toolbar - Top control bar
    # ============================================================
    def _build_toolbar(self):
        """
        Build the top toolbar containing:
        - App title label
        - Network interface dropdown selector
        - Start/Stop capture buttons
        - Load PCAP and Clear buttons
        - Status indicator and packet count
        """
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=8, pady=(8, 4))

        # Application title in accent color
        tk.Label(
            bar,
            text="NetSniffer",
            font=("Segoe UI", 13, "bold"),
            bg=C["bg"],
            fg=C["accent"]
        ).pack(side="left", padx=(0, 14))

        vertical_separator(bar)

        # --- Interface selector ---
        ttk.Label(bar, text="Interface:").pack(side="left", padx=(10, 4))

        self._iface_var = tk.StringVar()

        iface_combo = ttk.Combobox(
            bar,
            textvariable=self._iface_var,
            width=18,
            font=("Segoe UI", 10)
        )
        iface_combo.pack(side="left", padx=(0, 10))

        # Populate the dropdown with available network interfaces
        self._populate_interfaces(iface_combo)

        # --- Start button (teal) ---
        self._btn_start = ttk.Button(
            bar,
            text="Start",
            style="Start.TButton",
            command=self._start_capture,
        )
        self._btn_start.pack(side="left", padx=4)

        # --- Stop button (red, initially disabled) ---
        self._btn_stop = ttk.Button(
            bar,
            text="Stop",
            style="Stop.TButton",
            command=self._stop_capture,
            state="disabled"
        )
        self._btn_stop.pack(side="left", padx=4)

        vertical_separator(bar)

        # --- File operations ---
        ttk.Button(
            bar,
            text="Load PCAP",
            command=self._load_file
        ).pack(side="left", padx=4)

        ttk.Button(
            bar,
            text="Clear",
            command=self._clear_packets
        ).pack(side="left", padx=4)

        vertical_separator(bar)

        # --- Status display (right side of toolbar) ---
        self._status_var = tk.StringVar(value="Idle")

        self._status_label = tk.Label(
            bar,
            textvariable=self._status_var,
            font=("Segoe UI", 10),
            bg=C["bg"],
            fg=C["muted"]
        )
        self._status_label.pack(side="right", padx=8)

        # Packet count display
        self._count_var = tk.StringVar(value="0 packets")

        ttk.Label(
            bar,
            textvariable=self._count_var,
            font=("Segoe UI", 9),
            foreground=C["muted"],
        ).pack(side="right", padx=16)

    def _populate_interfaces(self, combo_box):
        """
        Detect and populate available network interfaces.
        Tries Windows-specific detection first (for named interfaces),
        then falls back to generic scapy interface list for macOS/Linux.
        Filters out Windows driver duplicates that clutter the dropdown.
        """
        try:
            # Windows: get friendly interface names
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            seen = set()
            names = []
            for i in ifaces:
                name = i.get("name", "")
                # Skip filter driver duplicates (they have a dash+suffix pattern)
                if name and name not in seen and not any(
                    name.endswith(s) for s in [
                        "LightWeight Filter-0000", "Packet Driver (NPCAP)-0000",
                        "Packet Scheduler-0000", "WiFi Filter Driver-0000",
                        "MAC Layer LightWeight Filter-0000"
                    ]
                ):
                    seen.add(name)
                    names.append(name)
            combo_box["values"] = names
            if names:
                combo_box.set(names[0])
        except Exception:
            try:
                # macOS/Linux: use generic interface list
                from scapy.arch import get_if_list
                interfaces = get_if_list()
                combo_box["values"] = interfaces
                if interfaces:
                    combo_box.set(interfaces[0])
            except Exception:
                # No interfaces found at all
                combo_box["values"] = []
                combo_box.set("")

    # ============================================================
    # Filter Bar - Protocol, IP, and port filters
    # ============================================================
    def _build_filter_bar(self):
        """
        Build the filter bar below the toolbar.
        Contains dropdown for protocol and text entries for:
        - Source IP, Destination IP
        - Source Port, Destination Port
        Plus Apply and Clear Filters buttons.
        Protocol dropdown triggers filter immediately on selection.
        """
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=8, pady=(0, 6))

        ttk.Label(
            bar,
            text="Filters:",
            font=("Segoe UI", 9, "bold"),
            foreground=C["muted"]
        ).pack(side="left", padx=(0, 10))

        # --- Protocol dropdown filter ---
        ttk.Label(bar, text="Protocol:").pack(side="left", padx=(0, 4))

        self._proto_var = tk.StringVar()

        proto_combo = ttk.Combobox(
            bar,
            textvariable=self._proto_var,
            width=9,
            state="readonly",
            values=["", "TCP", "UDP", "ICMP", "ICMPv6", "DNS", "ARP", "IPv6"]
        )
        proto_combo.pack(side="left", padx=(0, 14))
        # Auto-apply filter when protocol selection changes
        proto_combo.bind("<<ComboboxSelected>>", lambda event: self._apply_filters())

        # --- Source IP text filter ---
        ttk.Label(bar, text="Src IP:").pack(side="left", padx=(0, 4))

        self._src_ip_var = tk.StringVar()

        ttk.Entry(
            bar,
            textvariable=self._src_ip_var,
            width=16,
        ).pack(side="left", padx=(0, 14))

        # --- Destination IP text filter ---
        ttk.Label(bar, text="Dst IP:").pack(side="left", padx=(0, 4))

        self._dst_ip_var = tk.StringVar()

        ttk.Entry(
            bar,
            textvariable=self._dst_ip_var,
            width=16
        ).pack(side="left", padx=(0, 14))

        # --- Source Port text filter ---
        ttk.Label(bar, text="Src Port:").pack(side="left", padx=(0, 4))

        self._src_port_var = tk.StringVar()

        ttk.Entry(
            bar,
            textvariable=self._src_port_var,
            width=7
        ).pack(side="left", padx=(0, 14))

        # --- Destination Port text filter ---
        ttk.Label(bar, text="Dst Port:").pack(side="left", padx=(0, 4))

        self._dst_port_var = tk.StringVar()

        ttk.Entry(
            bar,
            textvariable=self._dst_port_var,
            width=7
        ).pack(side="left", padx=(0, 14))

        # --- Apply and Clear buttons ---
        ttk.Button(
            bar,
            text="Apply",
            command=self._apply_filters
        ).pack(side="left", padx=4)

        ttk.Button(
            bar,
            text="Clear Filters",
            command=self._clear_filters
        ).pack(side="left", padx=4)

        # Filter status label (shows "Showing X of Y packets" when filtered)
        self._filter_label_var = tk.StringVar()

        tk.Label(
            bar,
            textvariable=self._filter_label_var,
            font=("Segoe UI", 9, "italic"),
            bg=C["bg"],
            fg=C["accent"]
        ).pack(side="left", padx=10)

    # ============================================================
    # Main Body - Packet table and lower detail panels
    # ============================================================
    def _build_body(self):
        """
        Build the main content area using a vertical PanedWindow.
        Top section: packet table (weight 3 = takes more space)
        Bottom section: detail tabs + statistics panel (weight 2)
        The pane divider can be dragged to resize sections.
        """
        self._main_pane = ttk.PanedWindow(self.root, orient="vertical")
        self._main_pane.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self._build_packet_table()
        self._build_lower_panel()

    # ============================================================
    # Packet Table - Main list of captured packets
    # ============================================================
    def _build_packet_table(self):
        """
        Build the packet list treeview with columns for:
        #, Time, Protocol, Src IP, Src Port, Dst IP, Dst Port, Length, Info
        Features: sortable columns, protocol-based row coloring,
        scrollbars, auto-scroll toggle, and row selection binding.
        """
        frame = ttk.Frame(self._main_pane)
        self._main_pane.add(frame, weight=3)

        # Define all column identifiers
        columns = (
            "#",         # Sequential packet number
            "Time",      # Capture timestamp (HH:MM:SS.ms)
            "Protocol",  # Protocol name (TCP, UDP, etc.)
            "Src IP",    # Source IP address
            "Src Port",  # Source port number
            "Dst IP",    # Destination IP address
            "Dst Port",  # Destination port number
            "Length",    # Packet size in bytes
            "Info",      # Protocol-specific info string
        )

        # Create the treeview with headings only (no tree column)
        self._tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="browse"   # Only one row selectable at a time
        )

        # Column width configuration
        widths = {
            "#":        52,
            "Time":     100,
            "Protocol": 80,
            "Src IP":   148,
            "Src Port": 72,
            "Dst IP":   148,
            "Dst Port": 72,
            "Length":   64,
            "Info":     420,
        }

        # Configure each column heading and width
        for column in columns:
            # Clicking a heading sorts by that column
            self._tree.heading(
                column,
                text=column,
                command=lambda selected_column=column: self._sort_column(selected_column)
            )
            self._tree.column(
                column,
                width=widths[column],
                minwidth=40,
                stretch=(column == "Info")  # Only Info column stretches to fill
            )

        # Apply protocol-specific row colors from the PROTO_TAGS dict
        for protocol, config in PROTO_TAGS.items():
            self._tree.tag_configure(protocol, **config)

        # Default tag for unrecognized protocols
        self._tree.tag_configure(
            "default",
            background=C["surface"],
            foreground=C["text"]
        )

        # Vertical scrollbar for the packet table
        y_scroll = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self._tree.yview
        )

        # Horizontal scrollbar for wide Info column
        x_scroll = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=self._tree.xview
        )

        # Connect scrollbars to treeview
        self._tree.configure(
            yscrollcommand=y_scroll.set,
            xscrollcommand=x_scroll.set
        )

        # Grid layout: treeview fills space, scrollbars on edges
        self._tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Bind row selection to show packet details and hex dump
        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)

        # Bottom strip with auto-scroll checkbox
        strip = ttk.Frame(frame)
        strip.grid(row=2, column=0, columnspan=2, sticky="w", pady=2)

        ttk.Checkbutton(
            strip,
            text="Auto-scroll",
            variable=self._autoscroll
        ).pack(side="left", padx=6)

    # ============================================================
    # Lower Panel - Detail tabs and statistics
    # ============================================================
    def _build_lower_panel(self):
        """
        Build the bottom section with a horizontal PanedWindow:
        Left side (weight 3): Notebook with Details and Hex tabs
        Right side (weight 1): Statistics label frame
        """
        pane = ttk.PanedWindow(self._main_pane, orient="horizontal")
        self._main_pane.add(pane, weight=2)

        # Detail notebook (left side)
        detail_outer = ttk.Frame(pane)
        pane.add(detail_outer, weight=3)
        self._build_detail_notebook(detail_outer)

        # Statistics panel (right side)
        stats_frame = ttk.LabelFrame(pane, text="Statistics", padding=10)
        pane.add(stats_frame, weight=1)
        self._build_stats_panel(stats_frame)

    def _build_detail_notebook(self, parent):
        """
        Build the tabbed notebook with two tabs:
        1. Packet Details - expandable tree showing protocol layers
        2. HEX / ASCII Dump - raw byte view of the entire packet
        """
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)

        # Tab 1: Protocol layer details
        layers_tab = ttk.Frame(notebook)
        notebook.add(layers_tab, text=" Packet Details ")
        self._build_layers_tree(layers_tab)

        # Tab 2: Hex and ASCII dump
        hex_tab = ttk.Frame(notebook)
        notebook.add(hex_tab, text=" HEX / ASCII Dump ")
        self._build_hex_panel(hex_tab)

    def _build_layers_tree(self, parent):
        """
        Build the protocol layer detail treeview.
        Displays packet info in an expandable tree structure:
        - Packet Summary (number, time, protocol, IPs, ports)
        - Ethernet II layer fields
        - IP layer fields
        - TCP/UDP/ICMP layer fields
        - DNS layer fields (if present)
        """
        self._layers_tree = ttk.Treeview(parent, show="tree", selectmode="browse")

        # Scrollbar for the detail tree
        y_scroll = ttk.Scrollbar(
            parent,
            orient="vertical",
            command=self._layers_tree.yview
        )
        self._layers_tree.configure(yscrollcommand=y_scroll.set)

        # Grid layout
        self._layers_tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")

        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

    def _build_hex_panel(self, parent):
        """
        Build the hex dump text panel.
        Shows three sections when a packet is selected:
        1. Full packet hex dump (offset | hex bytes | ASCII)
        2. Payload hex only
        3. Payload ASCII only
        Uses monospace font for proper hex alignment.
        """
        self._hex_text = tk.Text(
            parent,
            wrap="none",                     # No word wrap for hex alignment
            bg=C["hex_bg"],                  # Dark background
            fg=C["hex_fg"],                  # Green-tinted text
            insertbackground=C["text"],
            font=("Courier New", 10),        # Monospace for hex alignment
            relief="flat"
        )

        # Vertical and horizontal scrollbars
        y_scroll = ttk.Scrollbar(
            parent,
            orient="vertical",
            command=self._hex_text.yview
        )
        x_scroll = ttk.Scrollbar(
            parent,
            orient="horizontal",
            command=self._hex_text.xview
        )

        self._hex_text.configure(
            yscrollcommand=y_scroll.set,
            xscrollcommand=x_scroll.set
        )

        # Grid layout
        self._hex_text.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        # Initial placeholder text
        self._hex_text.insert("end", "Select a packet to view hex and ASCII data.")
        self._hex_text.config(state="disabled")

    # ============================================================
    # Statistics Panel
    # ============================================================
    def _build_stats_panel(self, parent):
        """
        Build the statistics display panel showing:
        - Total packet count
        - Total bytes captured
        - Current packet rate (packets/sec)
        - Elapsed capture time
        - Per-protocol packet count breakdown
        Uses a grid layout with label-value pairs.
        """
        # StringVars that get updated by _update_stats_panel()
        self._total_packets_var = tk.StringVar(value="0")
        self._total_bytes_var = tk.StringVar(value="0 B")
        self._packet_rate_var = tk.StringVar(value="0.0 packets/sec")
        self._elapsed_var = tk.StringVar(value="0s")

        row = 0

        # Total Packets row
        ttk.Label(parent, text="Total Packets:").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Label(parent, textvariable=self._total_packets_var).grid(row=row, column=1, sticky="w", pady=4)
        row += 1

        # Total Bytes row
        ttk.Label(parent, text="Total Bytes:").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Label(parent, textvariable=self._total_bytes_var).grid(row=row, column=1, sticky="w", pady=4)
        row += 1

        # Packet Rate row
        ttk.Label(parent, text="Packet Rate:").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Label(parent, textvariable=self._packet_rate_var).grid(row=row, column=1, sticky="w", pady=4)
        row += 1

        # Elapsed Time row
        ttk.Label(parent, text="Elapsed Time:").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Label(parent, textvariable=self._elapsed_var).grid(row=row, column=1, sticky="w", pady=4)
        row += 1

        # Separator before protocol breakdown
        ttk.Separator(parent, orient="horizontal").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=10
        )
        row += 1

        # Protocol Counts header
        ttk.Label(
            parent,
            text="Protocol Counts",
            font=("Segoe UI", 10, "bold"),
            foreground=C["accent"]
        ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, 6))
        row += 1

        # Protocol count text area (read-only)
        self._protocol_stats_text = tk.Text(
            parent,
            height=12,
            bg=C["surface"],
            fg=C["text"],
            font=("Courier New", 10),
            relief="flat",
            wrap="word"
        )
        self._protocol_stats_text.grid(
            row=row, column=0, columnspan=2, sticky="nsew"
        )
        self._protocol_stats_text.insert("end", "No packets yet.")
        self._protocol_stats_text.config(state="disabled")

        # Allow the protocol text area to expand vertically
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(row, weight=1)

    # ============================================================
    # Capture Controls
    # ============================================================
    def _start_capture(self):
        """
        Start live packet capture on the selected network interface.
        Disables the Start button and enables Stop to prevent double-start.
        Updates the status label to show capturing state.
        """
        interface_name = self._iface_var.get().strip()

        # If no interface selected, pass None to let scapy auto-detect
        if interface_name == "":
            interface_name = None

        try:
            self._sniffer.start(interface_name)
            self._capturing = True
            self._btn_start.config(state="disabled")
            self._btn_stop.config(state="normal")
            self._status_var.set("Capturing")
            self._status_label.config(fg=C["accent"])
        except Exception as error:
            messagebox.showerror("Capture Error", str(error))
            self._status_var.set("Capture failed")
            self._status_label.config(fg=C["red"])

    def _stop_capture(self):
        """
        Stop the active packet capture.
        Re-enables Start button and disables Stop.
        """
        self._sniffer.stop()
        self._capturing = False
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._status_var.set("Stopped")
        self._status_label.config(fg=C["muted"])

    def _load_file(self):
        """
        Open a file dialog to load a PCAP/PCAPNG file for offline analysis.
        All packets from the file are parsed and displayed in the table.
        """
        file_path = filedialog.askopenfilename(
            title="Open Packet Capture File",
            filetypes=[
                ("Packet capture Files", "*.pcap *.pcapng"),
                ("All Files", "*.*")
            ]
        )

        if file_path == "":
            return

        try:
            count = self._sniffer.load_from_file(file_path)
            self._poll_queue()       # Process all loaded packets immediately
            self._apply_filters()    # Refresh display with current filters
            self._status_var.set(f"Loaded {count} packets")
            self._status_label.config(fg=C["accent"])
        except Exception as error:
            messagebox.showerror("File Error", str(error))
            self._status_var.set("File load failed")
            self._status_label.config(fg=C["red"])

    def _clear_packets(self):
        """
        Clear all captured packets and reset the entire application state.
        Stops any active capture, empties all data structures,
        resets statistics, and clears all GUI panels.
        """
        self._stop_capture()

        # Clear all data structures
        self._all_packets.clear()
        self._packet_times.clear()
        self._visible_packet_indexes.clear()
        self._packet_counter = 0
        self._stats.reset()

        # Drain any remaining packets from the queue
        while not self._packet_queue.empty():
            self._packet_queue.get()

        # Clear the packet table
        for row in self._tree.get_children():
            self._tree.delete(row)

        # Reset detail and hex panels to placeholder state
        self._clear_details()
        self._clear_hex()
        self._update_stats_panel()

        # Reset status displays
        self._count_var.set("0 packets")
        self._filter_label_var.set("")
        self._status_var.set("Packets cleared")
        self._status_label.config(fg=C["muted"])

    # ============================================================
    # Packet Queue Processing (Thread-Safe)
    # ============================================================
    def _on_packet_received(self, packet):
        """
        Callback invoked by the Sniffer from the capture thread.
        Puts the parsed packet into a thread-safe queue.
        The GUI thread polls this queue via _poll_queue().
        This separation prevents tkinter crashes from cross-thread access.
        """
        self._packet_queue.put(packet)

    def _poll_queue(self):
        """
        Periodic callback (every 100ms) that drains the packet queue
        and adds new packets to the GUI. This is the bridge between
        the capture thread and the tkinter main thread.

        For each packet:
        1. Assigns a sequential number and timestamp
        2. Stores it in the master packet list
        3. Records it in statistics
        4. If it passes the current filter, adds it to the table
        5. Auto-scrolls to the newest packet if enabled
        """
        updated = False

        # Process all available packets from the queue
        while not self._packet_queue.empty():
            packet = self._packet_queue.get()

            # Assign GUI-specific metadata
            self._packet_counter += 1
            packet["_gui_number"] = self._packet_counter
            packet["_gui_time"] = fmt_time()

            # Store in master list and record statistics
            self._all_packets.append(packet)
            self._packet_times.append(packet["_gui_time"])
            self._stats.record(packet)

            # Index of this packet in the master list
            packet_index = len(self._all_packets) - 1

            # Only add to table if it passes the current filter
            if self._filter.matches(packet):
                self._visible_packet_indexes.append(packet_index)
                self._insert_packet_row(packet, packet_index)
                updated = True

        # Auto-scroll to the last row if new packets were added
        if updated and self._autoscroll.get():
            rows = self._tree.get_children()
            if rows:
                self._tree.see(rows[-1])

        # Update packet count display
        self._count_var.set(f"{len(self._all_packets)} packets")

        # Schedule next poll in 100ms
        self.root.after(100, self._poll_queue)

    def _insert_packet_row(self, packet, packet_index):
        """
        Insert a single packet as a row in the treeview table.
        The packet_index is used as the row ID (iid) so we can
        look up the full packet data when a row is selected.
        Tags determine the row color based on protocol type.
        """
        protocol = packet.get("protocol", "Unknown")
        # Use protocol name as tag for coloring, fall back to "default"
        tag = protocol if protocol in PROTO_TAGS else "default"

        # Build the tuple of column values in display order
        values = (
            packet.get("_gui_number", packet_index + 1),
            packet.get("_gui_time", ""),
            protocol,
            packet.get("src_ip", "N/A"),
            packet.get("src_port", "N/A"),
            packet.get("dst_ip", "N/A"),
            packet.get("dst_port", "N/A"),
            packet.get("length", "N/A"),
            packet.get("info", "")
        )

        # Insert row with packet_index as unique ID
        self._tree.insert(
            "",
            "end",
            iid=str(packet_index),
            values=values,
            tags=(tag,)
        )

    # ============================================================
    # Filter Application
    # ============================================================
    def _apply_filters(self):
        """
        Read all filter fields, apply them, and rebuild the packet table.
        Only packets matching ALL active filters are shown.
        This completely rebuilds the table rather than hiding rows,
        which ensures correct behavior when filters change.
        """
        # Push current filter values into the PacketFilter engine
        self._filter.set_filter("protocol", self._proto_var.get())
        self._filter.set_filter("src_ip", self._src_ip_var.get())
        self._filter.set_filter("dst_ip", self._dst_ip_var.get())
        self._filter.set_filter("src_port", self._src_port_var.get())
        self._filter.set_filter("dst_port", self._dst_port_var.get())

        # Clear the entire table
        for row in self._tree.get_children():
            self._tree.delete(row)

        self._visible_packet_indexes.clear()

        # Re-insert only packets that match the filter
        for index, packet in enumerate(self._all_packets):
            if self._filter.matches(packet):
                self._visible_packet_indexes.append(index)
                self._insert_packet_row(packet, index)

        # Clear detail panels since selection is lost
        self._clear_details()
        self._clear_hex()

        # Update the filter status label
        if self._filter.has_active_filters():
            self._filter_label_var.set(
                f"Showing {len(self._visible_packet_indexes)} of {len(self._all_packets)} packets"
            )
        else:
            self._filter_label_var.set("")

    def _clear_filters(self):
        """
        Reset all filter inputs to empty and reshow all packets.
        Clears the protocol dropdown and all text entry fields,
        then reapplies (which now shows everything).
        """
        self._proto_var.set("")
        self._src_ip_var.set("")
        self._dst_ip_var.set("")
        self._src_port_var.set("")
        self._dst_port_var.set("")

        self._filter.clear_all()
        self._apply_filters()

    # ============================================================
    # Column Sorting
    # ============================================================
    def _sort_column(self, column):
        """
        Sort the packet table by the clicked column.
        Attempts numeric sorting first (for #, ports, length),
        falls back to alphabetical for text columns.
        Rearranges rows in-place without modifying the data.
        """
        rows = list(self._tree.get_children())

        def get_sort_value(row_id):
            value = self._tree.set(row_id, column)
            try:
                return int(value)        # Numeric sort for numbers
            except ValueError:
                return value.lower()     # Case-insensitive text sort

        rows.sort(key=get_sort_value)

        # Reposition each row in sorted order
        for index, row_id in enumerate(rows):
            self._tree.move(row_id, "", index)

    # ============================================================
    # Packet Selection - Detail and Hex Display
    # ============================================================
    def _on_row_select(self, event):
        """
        Handle packet row selection in the treeview.
        Retrieves the full packet data using the row ID (which is
        the index into _all_packets) and updates both the detail
        tree and hex dump panels.
        """
        selected_rows = self._tree.selection()

        if not selected_rows:
            return

        # Row ID is the packet index in the master list
        packet_index = int(selected_rows[0])
        packet = self._all_packets[packet_index]

        self._show_packet_details(packet)
        self._show_packet_hex(packet)

    def _show_packet_details(self, packet):
        """
        Populate the layer detail treeview for the selected packet.
        Creates two sections:
        1. Packet Summary - flat list of all key fields
        2. Protocol Layers - expandable nodes for each protocol layer
           (Ethernet, IP, TCP/UDP/ICMP, DNS, etc.)
        Each layer node contains its parsed header fields.
        """
        # Clear previous details
        for item in self._layers_tree.get_children():
            self._layers_tree.delete(item)

        # --- Section 1: Packet Summary ---
        summary = self._layers_tree.insert(
            "", "end",
            text="Packet Summary",
            open=True           # Expanded by default
        )

        # List of all summary fields to display
        summary_fields = [
            ("Number", packet.get("_gui_number", "N/A")),
            ("Time", packet.get("_gui_time", "N/A")),
            ("Protocol", packet.get("protocol", "N/A")),
            ("Length", f"{packet.get('length', 'N/A')} bytes"),
            ("Source MAC", packet.get("src_mac", "N/A")),
            ("Destination MAC", packet.get("dst_mac", "N/A")),
            ("Source IP", packet.get("src_ip", "N/A")),
            ("Destination IP", packet.get("dst_ip", "N/A")),
            ("Source Port", packet.get("src_port", "N/A")),
            ("Destination Port", packet.get("dst_port", "N/A")),
            ("TTL/Hop Limit", packet.get("ttl", "N/A")),
            ("IP Version", packet.get("ip_version", "N/A")),
            ("Fragment Flags", packet.get("frag_flags", "N/A")),
            ("Fragment Offset", packet.get("frag_offset", "N/A")),
            ("TCP Flags", packet.get("tcp_flags", "N/A")),
            ("Info", packet.get("info", "")),
        ]

        # Insert each field as a child of the summary node
        for name, value in summary_fields:
            self._layers_tree.insert(
                summary, "end",
                text=f"{name}: {value}"
            )

        # --- Section 2: Protocol Layer Details ---
        layers = packet.get("layers", [])

        if len(layers) == 0:
            self._layers_tree.insert(
                "", "end",
                text="No layer details available"
            )
        else:
            # Each layer becomes an expandable node
            for layer in layers:
                layer_name = layer.get("name", "Unknown Layer")

                layer_node = self._layers_tree.insert(
                    "", "end",
                    text=layer_name,
                    open=True    # All layers expanded by default
                )

                # Insert each header field as a child of the layer
                for field_name, field_value in layer.get("fields", []):
                    self._layers_tree.insert(
                        layer_node, "end",
                        text=f"{field_name}: {field_value}"
                    )

    def _show_packet_hex(self, packet):
        """
        Display the hex dump for the selected packet.
        Shows three sections:
        1. Full packet hex dump (all layers, offset | hex | ASCII)
        2. Payload hex only (application data)
        3. Payload ASCII only (printable characters)
        """
        self._hex_text.config(state="normal")
        self._hex_text.delete("1.0", "end")

        raw_packet = packet.get("raw_packet")

        # Section 1: Full packet hex dump using format_full_hex()
        self._hex_text.insert("end", "Full Packet Hex Dump\n")
        self._hex_text.insert("end", "-" * 80 + "\n")

        if raw_packet is not None:
            self._hex_text.insert("end", format_full_hex(raw_packet))
        else:
            self._hex_text.insert("end", "No raw packet data available.")

        # Section 2: Payload hex values only
        self._hex_text.insert("end", "\n\nPayload Hex\n")
        self._hex_text.insert("end", "-" * 80 + "\n")

        payload_hex = packet.get("payload_hex", "")

        if payload_hex:
            self._hex_text.insert("end", payload_hex)
        else:
            self._hex_text.insert("end", "No payload found.")

        # Section 3: Payload ASCII representation
        self._hex_text.insert("end", "\n\nPayload ASCII\n")
        self._hex_text.insert("end", "-" * 80 + "\n")

        payload_ascii = packet.get("payload_ascii", "")

        if payload_ascii:
            self._hex_text.insert("end", payload_ascii)
        else:
            self._hex_text.insert("end", "No payload found.")

        # Lock the text widget to prevent user editing
        self._hex_text.config(state="disabled")

    # ============================================================
    # Panel Reset Helpers
    # ============================================================
    def _clear_details(self):
        """Reset the detail treeview to its default placeholder state."""
        for item in self._layers_tree.get_children():
            self._layers_tree.delete(item)

        self._layers_tree.insert(
            "", "end",
            text="Select a packet to view details."
        )

    def _clear_hex(self):
        """Reset the hex dump panel to its default placeholder state."""
        self._hex_text.config(state="normal")
        self._hex_text.delete("1.0", "end")
        self._hex_text.insert("end", "Select a packet to view hex and ASCII data.")
        self._hex_text.config(state="disabled")

    # ============================================================
    # Statistics Update Loop
    # ============================================================
    def _update_stats_panel(self):
        """
        Refresh the statistics panel with current data from the Stats module.
        Updates total packets, bytes, rate, elapsed time, and protocol counts.
        Runs on a 1-second loop via root.after() to keep stats current
        during live capture without blocking the GUI.
        """
        summary = self._stats.get_summary()

        # Update the StringVar labels
        self._total_packets_var.set(str(summary["total_packets"]))
        self._total_bytes_var.set(fmt_bytes(summary["total_bytes"]))
        self._packet_rate_var.set(f"{summary['packets_per_second']} packets/sec")
        self._elapsed_var.set(summary["elapsed_formatted"])

        # Rebuild the protocol count text area
        self._protocol_stats_text.config(state="normal")
        self._protocol_stats_text.delete("1.0", "end")

        protocol_counts = summary["protocol_counts"]

        if len(protocol_counts) == 0:
            self._protocol_stats_text.insert("end", "No packets yet.")
        else:
            # Show each protocol and its count, sorted alphabetically
            for protocol in sorted(protocol_counts):
                count = protocol_counts[protocol]
                self._protocol_stats_text.insert("end", f"{protocol}: {count}\n")

        self._protocol_stats_text.config(state="disabled")

        # Schedule next update in 1 second
        self.root.after(1000, self._update_stats_panel)


# ============================================================
# Entry Point - Launch the application
# ============================================================
def main():
    """Create the root Tk window and start the main event loop."""
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()