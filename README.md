# README #

packet-analyzer reads a packet and produces a detailed summary of the packet. 
The program will extract and display the different headers of the captured packet in the file datafile. 
1. It displays the ethernet header fields of the captured frames.
2. If the ethernet frame contains an IP datagram, it prints the IP header. 
3. It prints the packets encapsulated in the IP datagram. TCP, UDP, or ICMP packets can be encapsulated in the IP packet.

# Interface #
packet-analyzer should run as a shell command. The syntax of the command is the following:

% pktanalyzer datafile


