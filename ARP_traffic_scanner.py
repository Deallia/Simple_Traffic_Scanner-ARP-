
# id no# 620146170    
# name: Deallia Dunbar

import scapy.all as scapy
import optparse


# creating command line arguments
parser = optparse.OptionParser() 
parser.add_option( "--ip", dest="ip_range", help="Target IP range in CIDR notation (e.g., 192.168.1.0/24)")
(options, args) = parser.parse_args()
if not options.ip_range:
    parser.error("[-] Please specify a target IP range using --ip. Use --help for more info.")  #error handling


arp_request = scapy.ARP()        # creating an Arp packet object
arp_request.pdst = options.ip_range # setting ip address to be queried

# print (arp_request.summary())
# print(scapy.ls(scapy.ARP))


broadcast = scapy.Ether()        #creating an ethernet frame
broadcast.dst = "ff:ff:ff:ff:ff:ff" #setting mac address in ethernet frame
arp_request_broadcast = broadcast/arp_request

# print(arp_request_broadcast.show())
# print(broadcast.summary())


#sending a packet
answered, unanswered = scapy.srp(arp_request_broadcast, timeout = 1)


#parsing the answered list
for packet in answered:
    ip_add = packet[1].pdst
    mac_add = packet[1].hwsrc
    print("Packet   IP address: ", ip_add, ",  MAC address: ", mac_add)


