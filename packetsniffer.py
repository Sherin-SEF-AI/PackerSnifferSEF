import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, StringVar, Menu
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
import threading
import json

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Packet Sniffer")

        self.create_widgets()
        self.sniffing = False
        self.packet_logs = []
        self.packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

    def create_widgets(self):
        # Create a menu bar
        self.menubar = Menu(self.root)
        self.root.config(menu=self.menubar)

        # Create file menu
        file_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Start Sniffing", command=self.start_sniffing)
        file_menu.add_command(label="Stop Sniffing", command=self.stop_sniffing, state="disabled")
        file_menu.add_separator()
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Save Configuration", command=self.save_configuration)
        file_menu.add_command(label="Load Configuration", command=self.load_configuration)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Create view menu
        view_menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode)

        # Create a toolbar frame
        toolbar_frame = tk.Frame(self.root)
        toolbar_frame.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        # Filter expression
        tk.Label(toolbar_frame, text="Filter:").grid(row=0, column=0, padx=5)
        self.filter_entry = ttk.Entry(toolbar_frame, width=50)
        self.filter_entry.grid(row=0, column=1, padx=5)

        # Network interface selection
        tk.Label(toolbar_frame, text="Interface:").grid(row=0, column=2, padx=5)
        self.interface_var = StringVar()
        self.interface_menu = ttk.Combobox(toolbar_frame, textvariable=self.interface_var)
        self.interface_menu['values'] = get_if_list()
        self.interface_menu.grid(row=0, column=3, padx=5)
        self.interface_menu.current(0)

        # Protocol filter options
        tk.Label(toolbar_frame, text="Protocol:").grid(row=0, column=4, padx=5)
        self.protocol_var = StringVar(value="ALL")
        self.protocol_menu = ttk.Combobox(toolbar_frame, textvariable=self.protocol_var)
        self.protocol_menu['values'] = ["ALL", "TCP", "UDP", "ICMP"]
        self.protocol_menu.grid(row=0, column=5, padx=5)
        self.protocol_menu.current(0)

        # Real-time search
        tk.Label(toolbar_frame, text="Search:").grid(row=0, column=6, padx=5)
        self.search_entry = ttk.Entry(toolbar_frame, width=30)
        self.search_entry.grid(row=0, column=7, padx=5)
        self.search_entry.bind("<KeyRelease>", self.search_packets)

        # Create a scrolled text area for displaying packets
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=120, height=15)
        self.text_area.grid(row=1, column=0, columnspan=8, padx=10, pady=10)

        # Packet Table
        self.packet_table = ttk.Treeview(self.root, columns=("No", "Source", "Destination", "Protocol", "Info"), show="headings")
        self.packet_table.grid(row=2, column=0, columnspan=8, padx=10, pady=10)
        self.packet_table.heading("No", text="No")
        self.packet_table.heading("Source", text="Source")
        self.packet_table.heading("Destination", text="Destination")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.heading("Info", text="Info")
        self.packet_table.bind("<Double-1>", self.on_packet_select)

        # Statistics Panel
        self.stats_frame = tk.Frame(self.root)
        self.stats_frame.grid(row=3, column=0, columnspan=8, padx=10, pady=5, sticky=tk.W)

        self.tcp_count_label = tk.Label(self.stats_frame, text="TCP: 0")
        self.tcp_count_label.grid(row=0, column=0, padx=5)

        self.udp_count_label = tk.Label(self.stats_frame, text="UDP: 0")
        self.udp_count_label.grid(row=0, column=1, padx=5)

        self.icmp_count_label = tk.Label(self.stats_frame, text="ICMP: 0")
        self.icmp_count_label.grid(row=0, column=2, padx=5)

        self.other_count_label = tk.Label(self.stats_frame, text="Other: 0")
        self.other_count_label.grid(row=0, column=3, padx=5)

        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=4, column=0, columnspan=8, sticky=tk.W+tk.E)

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            log_entry = f"IP {ip_src} -> {ip_dst} [{proto}]"

            protocol = "Other"
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                log_entry += f" TCP {sport} -> {dport}"
                protocol = "TCP"
                self.packet_count["TCP"] += 1
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                log_entry += f" UDP {sport} -> {dport}"
                protocol = "UDP"
                self.packet_count["UDP"] += 1
            elif ICMP in packet:
                log_entry += f" ICMP Type {packet[ICMP].type}"
                protocol = "ICMP"
                self.packet_count["ICMP"] += 1
            else:
                self.packet_count["Other"] += 1
            if Raw in packet:
                log_entry += f" Data: {packet[Raw].load}"

            self.packet_logs.append(log_entry)
            self.text_area.insert(tk.END, log_entry + "\n")
            self.text_area.yview(tk.END)

            # Insert into packet table
            self.packet_table.insert("", "end", values=(len(self.packet_logs), ip_src, ip_dst, protocol, log_entry))

            # Update statistics
            self.update_stats()

    def start_sniffing(self):
        self.sniffing = True
        self.text_area.insert(tk.END, "Started sniffing...\n")
        self.status_bar.config(text="Sniffing in progress...")
        self.packet_logs.clear()

        filter_exp = self.filter_entry.get()
        interface = self.interface_var.get()
        protocol = self.protocol_var.get()

        if protocol != "ALL":
            filter_exp += f" {protocol.lower()}"

        self.sniffer_thread = threading.Thread(target=self.sniff_packets, args=(filter_exp, interface))
        self.sniffer_thread.start()

        # Enable stop menu item
        self.menubar.entryconfig("File", state="normal")
        self.menubar.entryconfig(2, state="normal")

    def stop_sniffing(self):
        self.sniffing = False
        self.text_area.insert(tk.END, "Stopped sniffing.\n")
        self.status_bar.config(text="Sniffing stopped.")

        # Disable stop menu item
        self.menubar.entryconfig(2, state="disabled")

    def sniff_packets(self, filter_exp, interface):
        try:
            sniff(prn=self.packet_callback, filter=filter_exp, iface=interface, store=0, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            self.stop_sniffing()

    def export_logs(self):
        if not self.packet_logs:
            messagebox.showinfo("Info", "No logs to export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write("\n".join(self.packet_logs))
            messagebox.showinfo("Success", "Logs exported successfully.")

    def save_configuration(self):
        config = {
            "filter": self.filter_entry.get(),
            "interface": self.interface_var.get(),
            "protocol": self.protocol_var.get()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "w") as file:
                json.dump(config, file)
            messagebox.showinfo("Success", "Configuration saved successfully.")

    def load_configuration(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "r") as file:
                config = json.load(file)
                self.filter_entry.delete(0, tk.END)
                self.filter_entry.insert(0, config["filter"])
                self.interface_var.set(config["interface"])
                self.protocol_var.set(config["protocol"])
            messagebox.showinfo("Success", "Configuration loaded successfully.")

    def toggle_dark_mode(self):
        bg_color = "black" if self.text_area.cget("bg") == "white" else "white"
        fg_color = "white" if bg_color == "black" else "black"
        self.text_area.config(bg=bg_color, fg=fg_color)

    def update_stats(self):
        self.tcp_count_label.config(text=f"TCP: {self.packet_count['TCP']}")
        self.udp_count_label.config(text=f"UDP: {self.packet_count['UDP']}")
        self.icmp_count_label.config(text=f"ICMP: {self.packet_count['ICMP']}")
        self.other_count_label.config(text=f"Other: {self.packet_count['Other']}")

    def search_packets(self, event):
        search_term = self.search_entry.get().lower()
        for i in self.packet_table.get_children():
            values = self.packet_table.item(i, "values")
            if any(search_term in str(value).lower() for value in values):
                self.packet_table.selection_set(i)
                self.packet_table.see(i)
                break

    def on_packet_select(self, event):
        selected_item = self.packet_table.selection()[0]
        packet_info = self.packet_table.item(selected_item, "values")
        self.text_area.insert(tk.END, f"Selected Packet: {packet_info}\n")
        self.text_area.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

