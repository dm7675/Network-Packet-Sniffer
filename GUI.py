'''
@ASSESSME.USERID: [Your Project Group Name]
@ASSESSME.AUTHOR: [Author Name] - [RIT Credentials]
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY: LOW
'''


import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import queue
import time

from Sniffer import Sniffer
from Filter import PacketFilter
from Stats import Stats
from Parser import format_full_hex


PROTO_TAGS ={
    "TCP": {"background" : "#0d2f4a", "foreground":"#7db9e8" },
    "UDP": {"background" : "#0d3318", "foreground":"#7ec87e" },
    "ICMP": {"background" : "#302c00", "foreground":"#e0cc66" },
    "ICMPv6": {"background" : "#302c00", "foreground":"#e0cc66" },
    "DNS": {"background" : "#25123a", "foreground":"#c07ee8" },
    "ARP": {"background" : "#331a00", "foreground":"#e8a07e" },
    "IPv6": {"background" : "#002233", "foreground":"#66c8e8" },

}

C ={
    "bg":"#171614",
    "surface":"#1c1b19",
    "surface2":"#222120",
    "border":"#333230",
    "text":"#cdccca",
    "muted":"#797876",
    "faint":"#4a4948",
    "accent":"#4f98a3",
    "accent2":"#3a7a85",
    "red":"#a13544",
    "sel":"#1a3a5c",
    "hex_bg":"#141312",
    "hex_fg":"#b5cea8",
}


def fmt_time():
    t=time.time()
    ms=int((t%1)* 1000)
    return time.strftime("%H:%M:%S")+ f".{ms:03d}"


def vertical_separator(parent):
    ttk.Separator(parent, orient="vertical").pack(
        side="left",
        fill="y",
        padx=10,
        pady=3
    )

class PacketSnifferGUI:
    def __init__(self, root):
        self.root=root
        self.root.title("NetSniffer-Packet Analyzer")
        self.root.geometry("1440x860")
        self.root.minsize(1000, 640)
        self.root.configure(bg=C["bg"])

        self._filter= PacketFilter()
        self._stats=Stats()
        self._sniffer=Sniffer(self._on_pacKet_recieved)

        self._packet_queue-queue.Queue()
        self._all_packets=[]
        self._packet_times=[]
        self._visibel_packet_indexes=[]

        self._packet_counter=0
        self._capturing=False
        self._autoscroll=tk.BooleanVar(value=True)

        self._build_styles()
        self._build_toolbar()
        self._build_filter_bar()

        ttk.Separator(self.root, orient="horizontal").pack(fill="x")

        self._build_body()
        self._poll_queue()
        self._update_stats_panel()
    def _build_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(
            ".",
            background=C["bg"],
            foreground=C["text"],
            fieldbackground=C["surface2"],
            bordercolor=C["border"],
            troughcolor=C["surface"],
            font=("Segoe UI", 10),
        )

        style.configure("TFrame", background=C["bg"])
        style.configure("Tlabe;", background=C["bg"], foreground=C["text"])
        style.configure("Tseparator", background=C["border"])
        style.configure("TPanewindow", background=C["bg"])

        style.configure(
            "TButton",
            background=C["surface2"],
            foreground=C["text"],
            bordercolor=C["border"],
            padding=C(10,5),
            relief="flat",

        )

        style.map(
            "TButton",
            background=[
                ("active", C["border"]),
                ("pressed", C["bg"]),

            ],
        )

        style.configure(
            "Start.TButton",
            background=C["accent2"],
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),

        )


        style.map(
            "Start.TButton",
            background=[
                ("active", "#c04050"),
                ("disabled", C["faint"]),

            ],
        )

        style.configure(
            "TEntry",
            fieldbackground=C["surface2"],
            foreground="text",
            bordercolor=C["border"],
            insertcolor=C["text"],

        )

        style.configure(
            "TCombox",
            fieldbackground=C["surface2"],
            foreground="text",
            bordercolor=C["border"],
            insertcolor=C["muted"],

        )

        style.map(
            "TCombobox",
            fieldbackground=[("readonly", C["surface2"])],
            selectbackground=[("readonly", C["surface2"])],
        )

        style.configure(
            "Treeview",
            background=C["surface"],
            foreground=C["text"],
            fieldbackground=C["surface"],
            bordercolor=C["border"],
            rowheight=23,

        )


        style.map(
            "Treeview",
            background=[("selected", C["sel"])],
            foreground=[("selected", "#ffffff")],
        )

        style.configure("TNotebook", background=C["bg"], bordercolor=C["border"])




        style.configure(
            "TNotebook.Tab",
            background=C["surface"],
            foreground=C["muted"],
            padding=(14,5),
        )


        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", c["bg"]),
                ("active", C["text"])
            ],
            foreground=[
                ("selected", C["accent"]),
                ("active", C["text"])
            ],
        )

        style.configure("TLabelframe", background=C["bg"], bordercolor=C["border"])

        style.configure(
            "TLabelframe.Label",
            background=C["bg"],
            foreground=C["accent"],
            font=("Segoe UI", 9, "bold"),
        )

        style.configure(
            "TCheckbutton",
            background=C["bg"],
            foreground=C["muted"],
            foruscolor=C["accent"],
        )


        style.configure(
            "TScrollbar",
            background=C["surface2"],
            troughcolor=C["surface"],
            bordercolor=C["border"],
            arrowcolor=C["muted"],
        )


    def _build_toolbar(self):

        bar=ttk.Frame(self.root)
        bar.pack(fill="x", padx="8", pady=(8,4))

        tk.Label(

            bar,
            text="NetSniffer",
            font=("Segoe UI", 13, "bold"),
            bg=C["bg"],
            fg=C["accent"]
        ).pack(side="left", padx=(0,14))

        vertical_separator(bar)

        ttk.Label(bar, text="Interface:").pack(side="left", padx=(10,4))

        self._iface_var=tk.StringVar()

        self._iface_var=ttk.Combobox(
            bar,
            textvariable=self._iface_var,
            width=18,
            font=("Segoe UI", 10)
        )
        iface_combo.pack(side="left", padx=(0,10))

        self._populate_interfaces(iface_combo)

        self._btn_start= ttk.Button(
            bar,
            text="Stop",
            style="Stop.TButton",
            command=self._stop_capture,
            state="disabled"
        )
        self._btn_stop.pack(side="left", padx=4)

        vertical_separator(bar)

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

        self._status_var = tk.StringVar(value="Idle")

        self._status_label=tk.Label(

            bar,
            textvariable=self._status_var,
            font=("Segoe UI", 10),
            bg=C["bg"],
            fg=C["muted"]


        )
        self._status_label.pack(side="right", padx=8)

        self._count_var=tk.StringVar(value="0 packets")

        ttk.Label(
            bar,
            textvariable=self._count_var,
            font=("Segoe UI", 9),
            foreground=C["muted"],

        ).pack(side="right", padx=16)


        def _populate_interfaces(self, combo_box):
            try:
                from scapy.arch import get_if_list
                interfaces = get_if_list
                combo_box["values"] = interfaces

                if interfaces:
                    combo_box.set(interfaces[0])
            except Exception:
                combo_box["values"]= []
                combo_box.set("")

        def _build_filter_bar(self):
            bar= ttk.Frame(self.root)
            bar.pack(fill="x", padx=8, pady=(0, 6))

            ttk.Label(
                bar,
                text="Filters: "
                font="Segoi UI", 9,"bold",
                foreground=C["muted"]
            ).pack(side="left", padx=(0,10))

            ttk.Label(bar, text="Protocol: ").pack(side="left", padx=(0,4))

            self._proto_var=tk.StringVar()

            proto_combo= ttk.Combobox(
                bar,
                textvariable=self._proto_var,
                width=9,
                state="readonly",
                values=["", "TCP","UDP", "ICMP", "ICMPv6", "DNS", "ARP", "IPv6"]

            )

            proto_combo.pack(side="left", padx=(0,14))
            proto_combo.bind("<<ComboboxSelected>>", lambda event: self._apply_filters())
            
            ttk.Label(bar, text="Src IP: ").pack(side="left", padx=(0,4))

            self._src_ip_var = tk.StringVar()

            ttk.Entry(
                bar,
                textvariable=self._src_ip_var,
                widget=16,
            ).pack(side="left", padx=(0,14))


            ttk.Label(bar, text="Dst IP:").pack(side="left", padx=(0,4))

            self._dst_ip_var=tk.StringVar()

            ttk.Entry(
                bar,
                textvariable=self._dst_ip_var,
                width=16
            ).pack(side="left", padx=(0 ,14))




            ttk.Label(bar, text="Src Port:").pack(side="left", padx=(0,4))

            self._src_port_var=tk.StringVar()

            ttk.Entry(
                bar,
                textvariable=self._src_port_var,
                width=7
            ).pack(side="left", padx=(0,14))


            ttk.Label(bar, text="Dst Port:").pack(side="left", padx=(0,4))

            self._dst_port_var=tk.StringVar()


            ttk.Entry(
                bar,
                textvariable=self._dst_port_var,
                width=7
            ).pack(side="left", padx=(0,14))

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


            self._filter_label_var=tk.StringVar()


            tk.Label(
                bar,
                textvariable=self._filter_label_var,
                font=("Segoe UI", 9, "italic"),
                bg=C["bg"],
                fg=C["accent"]
            ).pack(side="left",padx=10)


        def _build_body(self):
            self._main_pane=ttk.PanedWindow(self.root, orient="vertical")
            self._main_pane.pack(fill="both", expand=True, padx=6, pady=(0,6))

            self._build_packet_table()
            self._build_lower_panel()

        def _build_packet_table(self):
            frame = ttk.Frame(self._main_pane)
            self._main_pane.add(frame, weigjt=3)

            columns=(
                "#",
                "Time",
                "Protocol",
                "Src IP",
                "Src Port",
                "Dst IP",
                "Dst Port",
                "Length",
                "Info",
                
                
            )


            self._tree = ttk.Treeview(
                frame,
                columns=columns,
                show="headings",
                selectmode="browse"
            )

            widths={

                "#": 52,
                "Time": 100,
                "Protocol": 80,
                "Src IP": 148,
                "Src Port": 72,
                "Dst IP": 148,
                "Dst Port": 72,
                "Length": 64,
                "Info": 420,
            }

            for column in columns:
                self._tree.heading(
                    column,
                    text=column,
                    command=lambda selected_column=column: self._sort_columns(selected_column)

                )

                self._tree_column(
                    column,
                    width=widths[column],
                    minwidth=40,
                    stretch=(column=="info")
                )
            for protocol, config in PROTO_TAGS.items():
                self._tree.tag_configure(protocol, **config)

            self._tree.tag_configure(
                "default",
                background=C["surface"],
                foreground=C["text"]
            )

            y_scroll=ttk.Scrollbar(
                frame,
                orient="vertical",
                command=self._tree.xview
            )

            self._tree.configure(
                yscrollcommand=y_scroll.set,
                xscrollcommand=x_scroll.set
            )

            self._tree.grid(row=0, column=0, sticky="nsew")
            y_scroll.grid(row=0, column=1, sticky="ns")
            x_scroll.grid(row=1, column=0, sticky="ew")


            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)

            self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

            strip = ttk.Frame(frame)
            strip.grid(row=2, column=0, columnspan=2, sticky="w", pady=2)

            ttl. Checkbutton(
                strip,
                text="Auto-scroll",
                variable=self._autoscroll
            ).pack(side="left", padx=6)


        def _build_lower_panel(self):