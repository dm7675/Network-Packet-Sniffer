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
            pane = ttl.PanedWindow(self._main_pane, orient="horizontal")
            self._main_pane-add(pane, weight=2)

            detail_outer = ttk.Frame(pane)
            pane.add(detail_outer, weight=3)
            self._build_detail_notebook(detail_outer)

            stats_frame = ttk.Label(pane, text="Statistics", padding=10)
            pane.add(stats_frame, weight=1)
            self._build_stats_panel(stats_frame)

        def _build_detail_notebook(self, parent):
            notebook = ttk.Notebook(parent)
            notebook.pack(fill="both", expand=True)

            layers_tab = ttk.Frame(notebook)
            notebook.add(layers_tab, text=" Packet Details ")
            self._build_layers_tree(layers_tab)

            hex_tab = ttk.Frame(notebook)
            notebook.add(hex_tab, text=" HEX / ASCIII Dump ")
            self._build_hex_panel(hex_tab)

        def _build_layers_tree(self, parent):
            self._layers_tree = ttk.Treeview(parent, show="tree", selectmode="browse")

            y_scroll = ttk.Scrollbar(
                parent,
                orient="vertical",
                command=self._layers_tree.yview
            )

            self._layers_tree.configure(yscrollcommand=y_scroll.set)

            self._layers_tree.grid(row=0, column=0, sticky="nsew")
            y_scroll.grid(row=0, column=1, sticky="ns")

            parent.rowconfigure(0, weight=1)
            parent.columnconfigure(0, weight=1)

        def _build_hex_panel(self, parent):
            self._hex_text = tk.Text(
                parent,
                wrap="none",
                bg=C["hex_bg"],
                fg=C["hex_fg"],
                insertbackgroun=C["text"]
                font=("Courier New", 10),
                relief="flat"
            )

            y_scroll = ttk.Scrollbar(
                parent,
                orient="vertical"
                command=self._hex_text.yview
            )

            x_scroll = ttk.Scrollbar(
                parent,
                orient="horizontal"
                command=self._hex_text.xview
            )

            self._hex_text.configure(
                yscrollcommand=y_scroll.set
                xscrollcommand=x_scroll.set
            )

            self._hex_text.grid(row=0, column=0, sticky="nsew")
            y_scroll.grid(row=0, column=1, sticky="ns")
            x_scroll.grid(row=1, column=0, sticky="ew")

            parent.rowconfigure(0,weight=1)
            parent.columnconfigure(0, weight=1)

            self._hex_text.insert("end", "Select a packet to view hex and ASCII data.")
            self._hex_text.config(state="disabled")
        
        def _build_stats_panel(self,parent):
            self._total_packets_var = tk.StringVar(value="0")
            self._total_bytes_var = tk.StringVar(value="0 B")
            self._packet_rate_var = tk.StringVar(value="0.0 packets/sec")
            self._elapsed_var = tk.StringVar(value="0s")

            row = 0

            ttk.Label(parent, text="Total Packets:").grid(row=row, column=0, sticky="w", pady=4)
            ttk.Label(parent, textvariable=self._total_packets_var).grid(row=row, column=1, sticky="w", pady=4)

            row +=1

            ttk.Label(parent, text="Total Bytes:").grid(row=row, column=0, sticky="w", pady=4)
            ttk.Label(parent, textvariable=self._total_bytes_var).grid(row=row, column=1, sticky="w", pady=4)

            row +=1

            ttk.Label(parent, text="Packet Rate:").grid(row=row, column=0, sticky="w", pady=4)
            ttk.Label(parent, textvariable=self._packet_rate_var).grid(row=row, column=1, sticky="w", pady=4)

            row +=1

            ttk.Label(parent, text="Elapsed Time:").grid(row=row, column=0, sticky="w", pady=4)
            ttk.Label(parent, textvariable=self._elapsed_var).grid(row=row, column=1, sticky="w", pady=4)

            row +=1

            ttk.Separator(parent, orient="horizontal").grid(
                row=row,
                column=0,
                columnspan=2,
                stacky="ew",
                pady=10
            )

            row +=1


            ttk.Label(
                parent,
                text="Protocol Counts",
                font=("Segoe UI", 10, "bold"),
                foreground=C["accent"]
            ).grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, 6))

            row += 1

            self._protocol_stats_text = tk.Text(
                parent,
                height=12,
                bg=C["surface"],
                fg=C["text"],
                font=("Courier New", 10),
                relief="flat"
                wrap="word"
            )
            
            self._protocol_stats_text.grid(
                row=row,
                column=0,
                columnspan=2,
                sticky="nsew"
            )

            self._protocol_stats_text.grid(
                row=roe,
                column=0,
                columnspan=2,
                sticky="nsew"
            )

            self._protocol_stats_text.insert("end", "No packets yet.")
            self._protocol_stats_text.config(state="disabled")

            parent.columnconfigure(1, weight=1)
            parent.rowconfigure(row, weight=1)

        def _start_capture(self):
            interface_name = self._iface_var.get().strip()

            if interface_name =="":
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
        self._sniffer.stop()
        self._capturing = False
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._status_var.set("Stopped")
        self._status_label.config(fg=C["muted"])

    def _load_file(self):
        file_path = filedialog.askopenfilename(
            title="Open Packet Capture File",
            filetypes=[
                ("Packet capture Files", "*.pcap *.pcapng"),
                ("All Files", "*.*")
            ]
        )

        if file_path =="":
            return

        try:
            count = self._sniffer.load_from_file(file_path)
            self._poll_queue()
            self._apply_filters()
            self._status_var.set(f"Loaded {count} packets")
            self._status_label.config(fg=C["accent"])
        except Exception as error:
            messagebox.showerror("File Error", str(error))
            self._status_var.set("File load failed")
            self._status_label.config(fg=C["red"])  


    def _clear_packets(self):
        self._stop_capture()

        self._all_packets.clear()
        self._packet_times.clear()
        self._visible_packet_indexes.clear()
        self._packet_counter = 0
        self._stats.reset()

        while not self._packet_queue.empty():
            self._packet_queue.get()

        for row in self._tree.get_children():
            self._tree.delete(row)

        self._clear_details()
        self._clear_hex()
        self._update_stats_panel()

        self._count_var.set("0 packets")
        self._filter_label_var.set("")
        self._status_var.set("Packets cleared")
        self._status_label.config(fg=C["muted"])

    def _on_packet_recieved(self, packet):
        self._packet_queue.put(packet)

    def _poll_queue(self):
        updated = False

        while not self._packet_queue.empty():
            packet = self._packet_queue.get()

            self._packet_counter +=1
            packet["_gui_number"] = self._packet_counter
            packet["_gui_time"] = fmt_time()

            self._all_packets.append(packet)
            self._packet_times.append(packet["_gui_time"])
            self._stats.record(packet)

            packet_index = len(self._all_packets) - 1

            if self._filter.matches(packet):
                self._visibel_packet_indexes.append(packet_index)
                self._insert_packet_row(packet, packet_index)
                updated = True
        
        if updated and self._autoscroll.get():
            rows = self._tree.get_children()

            if rows: self._tree.see(rows[-1])
        
        self._count_var.set(f"{len(self._all_packets)} packets")
        self.root.after(100, self._poll_queue)

    def _insert_packet_row(self, packet, packet_index):
        protocol = packet.get("protocol", "Unknown")
        tag = protocol if protocol in PROTO_TAGS else "defult"

        values = (
            packet.get("_gui_number", packet_index + 1),
            packet.get("_gui_time", ""),
            protocol,
            packet.get("src_ip", "N/A"),
            packet.get("src_port", "N/A"),
            packet.get("dst_ip", "N/A"),
            packet.get("src_port", "N/A"),
            packet.get("length", "N/A"),
            packet.get("info", "")
        )

        self._tree.insert(
            "",
            "end",
            iid=str(packet_index),
            values=values,
            tags=(tag,)
        )
    
    def _apply_filters(self):
        self._filter.set_filter("protocol", self._proto_var.get())
        self._filter.set_filter("src_ip", self._src_ip_var.get())
        self._filter.set_filter("dst_ip", self._dst_ip_var.get())
        self._filter.set_filter("src_port",  self._src_ip_var.get())
        self._filter.set_filter("dst_port", self._dst_ip_var.get())

        for row in self._tree.get_children():
            self._tree.delete(row)

        self._visible_packet_indexes.clear()

        for index, packet in enumerate(self._all_packets):
            if self._filter.matches(packet):
                self._visible_packet_indexes.append(index)
                self._insert_packet_row(packet, index)

        self._clear_details()
        self._clear_hex()

        if self._filter.has_active_filters():
            self._filter_label_var.set(
                f"Showing {len(selft._visible_packet_indexes)} of {len(self._all_packets)} packets"
            )
        else:
            self._filter_label_var.set("")

    def _clear_filters(self):
        self._proto_var.set("")
        self._src_ip_var.set("")
        self._dst_ip_var.set("")
        self._src_port_var.set("")
        self._dst_port_var.set("")

        self._filter.clear_all()
        self._apply_filters()

    def _sort_column(self, column):
        rows = list (self._tree.get_children())

        def get_sort_value(row_id):
            value = self._tree.set(row_id, column)

            try:
                return int(value)
            except ValueError:
                return value.lower()
            
        rows.sort(key=get_sort_value)

        for index, row_id in enumerate(rows):
            self._tree.move(row_id, "", index)

    def _on_row_select(self, event):
        selected_rows = self._tree.selection()

        if not selected_rows:
            return
        
        packet_index = int(selected_rows[0])
        packet = self._all_packets[packet_index]

        self._show_packet_details(packet)
        self._show_packet_hex(packet)

    def _show_packet_details(self, packet):
        for item in self._layers_tree.get_children():
            self._layers_tree.delete(item)

        summary = self._layers_tree.insert(
            "",
            "end",
            text="Packe Summary"
            oopet = True
        )

        summary_fields = [
            ("Number", packet.get("_gui_number", "N/A")),
            ("Time", packet.get("_gui_time", "N/A")),
            ("Protocol", packet.get("protocol", "N/A")),
            ("Length", f"{packet.get("length", "N/A")} bytes"),
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

        for name, value in summary_fields:
            self._layers_tree.insert(
                summary,
                "end",
                text=f"{name}: {value}"
            )

        layers = packet.get("layers", [])

        if len(layers) == 0:
            self._layers_tree.insert(
                "",
                "end",
                text="No layer details available"
            )
        else:
            for layer in layers:
                layer_name = layer.get("name", "Unknown Layer")

                layer_node = self._layers_tree.insert(
                    "",
                    "end",
                    text=layer_name,
                    open=True
                )

                for field_name, field_value in layer.get("fields", []):
                    self._layers_tree.insert(
                        layer_node,
                        "end",
                        text=f"{field_name}: {field_value}"
                    )

    def _show_packet_hex(self, packet):
        self._hex_text.config(state="normal")
        self._hex_text.delete("1.0", "end")

        raw_packet = packet.get("raw_packet")

        self._hex_text.insert("end", "Full Packet Hex Dump\n")
        self._hex_text.insert("end", "-" * 80 + "\n")

        if raw_packet is not None:
            self._hex_text.insert("end", format_full_hex(raw_packet))
        else:
            self._hex_text.insert("end", "No raw packet data available.")

        self._hex_text.insert("end", "\n\nPayload Hex\n")
        self._hex_text.insert("end", "-" * 80 + "\n")

        payload_hex = packet.get("payload_hex", "")

        if payload_hex:
            self._hex_text.insert("end", payload_hex)
        else:
            self._hex_text.insert("end", "No payload found.")

        self._hex_text.insert("end", "\n\nPayload ASCII\n")
        self._hex_text.insert("end", "-" * 80 + "\n")

        payload_ascii = packet.get("payload_ascii", "")

        if payload_ascii:
            self._hex_text.insert("end", payload_ascii)
        else:
            self._hex_text.insert("end", "No payload found.")

        self._hex_text.config(state="disabled")

    def _clear_details(self):
        for item in self._layers_tree.get_children():
            self._layers_tree.delete(item)

        self._layers_tree.insert(
            "",
            "end",
            text="Select a packet to view details."
        )

    def _clear_hex(self):
        self._hex_text.config(state="normal")
        self._hex_text.delete("1.0", "end")
        self._hex_text.insert("end", "Select a packet to view hex and ASCII data.")
        self._hex_text.config(state="disabled")

    def _update_stats_panel(self):
        summary = self._stats.get_summary()

        self._total_packets_var.set(str(summary["total_packets"]))
        self._total_bytes_var.set(fmt_bytes(summary["total_bytes"]))
        self._packet_rate_var.set(f"{summary['packets_per_second']} packets/sec")
        self._elapsed_var.set(summary["elapsed_formatted"])

        self._protocol_stats_text.config(state="normal")
        self._protocol_stats_text.delete("1.0", "end")

        protocol_counts = summary["protocol_counts"]

        if len(protocol_counts) == 0:
            self._protocol_stats_text.insert("end", "No packets yet.")
        else:
            for protocol in sorted(protocol_counts):
                count = protocol_counts[protocol]
                self._protocol_stats_text.insert("end", f"{protocol}: {count}\n")

        self._protocol_stats_text.config(state="disabled")

        self.root.after(1000, self._update_stats_panel)


def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()


        






