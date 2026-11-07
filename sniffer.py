from scapy.all import sniff, IP, TCP, UDP, ICMP
total_packets = 0
protocol_count = {
   "TCP":0,
   "UDP":0,
   "ICMP":0,
   "Other":0
}

def analyze_packet(packet):
    global total_packets
    
    if IP in packet:
        total_packets +=1
  
        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"
        protocol_count[protocol] +=1

        print("\n---------- PACKET DETAILS ----------")
        print("Source IP      :", source)
        print("Destination IP :", destination)
        print("Protocol       :", protocol)
        print("Packet Size    :", len(packet), "bytes")
        print("------------------------------------")
def display_summary():
    print("\n========== NETWORK SUMMARY ==========")
    print("Total Packets Captured:", total_packets)

    for protocol, count in protocol_count.items():
        print(protocol, "Packets:", count)

    

print("===================================")
print("===================================")
print("   CODEALPHA BASIC NETWORK SNIFFER")
print("===================================")
print("Capturing packets... Press Ctrl+C to stop.")

try:
    sniff(prn=analyze_packet, store=False)

except KeyboardInterrupt:
    print("\nNetwork packet capturing stopped.")

finally:
    display_summary()