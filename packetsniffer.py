# import tkinter as tk
# from tkinter import scrolledtext
# from scapy.all import *

# class PacketSnifferApp:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Packet Sniffer")

#         self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
#         self.text_area.pack(padx=10, pady=10)

#         self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
#         self.start_button.pack(pady=5)

#         self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing)
#         self.stop_button.pack(pady=5)

#         # Initialize the sniffing variable
#         self.sniffing = False

#     def start_sniffing(self):
#         if not self.sniffing:
#             self.sniffing = True
#             self.text_area.delete(1.0, tk.END)  # Clear text area before starting
#             sniff(prn=self.packet_callback, filter="tcp and port 12345", store=0)

#     def stop_sniffing(self):
#         self.sniffing = False

#     def packet_callback(self, packet):
#         if self.sniffing:
#             if packet.haslayer(IP) and packet.haslayer(TCP):
#                 ip_packet = packet.getlayer(IP)
#                 tcp_packet = packet.getlayer(TCP)
#                 if tcp_packet.dport == 12345 or tcp_packet.sport == 12345:
#                     self.text_area.insert(tk.END, f"Source IP: {ip_packet.src}, Destination IP: {ip_packet.dst}, "
#                                                   f"Source Port: {tcp_packet.sport}, Destination Port: {tcp_packet.dport}\n")
#                     # Log packet details to a file
#                     with open('ssl_packets.log', 'a') as f:
#                         f.write(f"Source IP: {ip_packet.src}, Destination IP: {ip_packet.dst}, "
#                                 f"Source Port: {tcp_packet.sport}, Destination Port: {tcp_packet.dport}\n")
#                 self.root.update_idletasks()  # Update GUI

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = PacketSnifferApp(root)
#     root.mainloop()

import socket
import threading
import time
from scapy.all import sniff, TCP, IP

def packet_sniffer(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_packet = packet.getlayer(IP)
        tcp_packet = packet.getlayer(TCP)
        raw_data = bytes(ip_packet)
    
        payload_data = bytes(tcp_packet.payload)
        ascii_string = bytes.decode('ascii')
        
        print(f"[*] Received raw data from client: {raw_data}")
        print(f"Source Port: {tcp_packet.sport}, Destination Port: {tcp_packet.dport}, Data: +{ascii_string}")
        # Log packet details to a file
        with open('packet_log.txt', 'w') as f:
            f.write(f"Source IP: {ip_packet.src}, Destination IP: {ip_packet.dst}, "
                    f"Source Port: {tcp_packet.sport}, Destination Port: {tcp_packet.dport}, Data:{ascii_string}\n")


            
def main():
    sniffer_thread = threading.Thread(target=lambda: sniff(filter="tcp and (port 12345)", prn=packet_sniffer, store=0))
    sniffer_thread.start()
main()
