# PacketSniffer-Pcap
This C program is a simple network packet sniffer that uses the pcap library to capture network packets. It focuses on filtering and analyzing HTTP (Hypertext Transfer Protocol) packets. The program extracts and displays various details from HTTP packets, including Ethernet and IP addresses, source and destination ports, and HTTP payload data.
## Prerequisites

Before using this packet sniffer, ensure you have the following prerequisites installed:

- **libpcap**: This library allows the program to capture network packets. You can install it on Linux using the package manager, e.g., `sudo apt-get install libpcap-dev`.

## Usage

To compile and use the packet sniffer, follow these steps:

1. **Compile the Program**: Use a C compiler (e.g., GCC) to compile the program:

```bash
# Compile the program
gcc -o packet_sniffer packet_sniffer.c -lpcap
# Replace 'packet_sniffer' with your desired executable name

# Run the program
./packet_sniffer [protocol] [number-of-packets]
# [protocol]: The protocol to filter for (e.g., "tcp", "udp").
# [number-of-packets]: The number of packets to capture.

# Select a Network Interface
# The program will display a list of available network interfaces. Enter the name of the interface you want to use for packet capture when prompted.

# Start Packet Capture
# The program will start capturing packets on the selected interface based on the specified protocol and packet count.

# View Captured Data
# As packets are captured, the program will display information such as Ethernet source and destination MAC addresses, source and destination IP addresses, source and destination ports, and the HTTP payload data.

# Extract Credentials and Cookies
# The program will also attempt to extract and display any username (uname), password (pass), or cookies (Cookie:) found in the HTTP payload data.

# Finish
# To stop the packet capture, press Ctrl+C. The program will display "Done with packet sniffing!" and exit.

