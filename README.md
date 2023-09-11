# PacketSniffer-Pcap
This C program is a simple network packet sniffer that uses the pcap library to capture network packets. It focuses on filtering and analyzing HTTP (Hypertext Transfer Protocol) packets. The program extracts and displays various details from HTTP packets, including Ethernet and IP addresses, source and destination ports, and HTTP payload data.
## Prerequisites

Before using this packet sniffer, ensure you have the following prerequisites installed:

- **libpcap**: This library allows the program to capture network packets. You can install it on Linux using the package manager, e.g., `sudo apt-get install libpcap-dev`.

## Usage

To compile and use the packet sniffer, follow these steps:

1. **Compile the Program**: Use a C compiler (e.g., GCC) to compile the program:

   ```bash
   gcc -o packet_sniffer packet_sniffer.c -lpcap
Replace packet_sniffer with your desired executable name.

Run the Program: Execute the compiled program with the following command:

bash
Copy code
./packet_sniffer [protocol] [number-of-packets]
[protocol]: The protocol to filter for (e.g., "tcp", "udp").
[number-of-packets]: The number of packets to capture.
Select a Network Interface: The program will display a list of available network interfaces. Enter the name of the interface you want to use for packet capture when prompted.

Start Packet Capture: The program will start capturing packets on the selected interface based on the specified protocol and packet count.

View Captured Data: As packets are captured, the program will display information such as Ethernet source and destination MAC addresses, source and destination IP addresses, source and destination ports, and the HTTP payload data.

Extract Credentials and Cookies: The program will also attempt to extract and display any username (uname), password (pass), or cookies (Cookie:) found in the HTTP payload data.

Finish: To stop the packet capture, press Ctrl+C. The program will display "Done with packet sniffing!" and exit.

Example
Here's an example of running the program to capture TCP packets on interface eth0:

bash
Copy code
./packet_sniffer tcp 10
This command will capture the first 10 TCP packets on interface eth0, display information about each packet, and extract credentials and cookies if present in the HTTP payload data.

Notes
This program focuses on HTTP packets, but you can modify it to capture and analyze packets of other protocols by changing the protocol argument in the command line.

Ensure that you have the necessary permissions to capture packets on the selected network interface. You may need superuser (root) privileges or appropriate permissions.

The program uses the libpcap library for packet capture and network interface management.

Be cautious when using packet capture tools, as they can capture sensitive information. Always use them responsibly and for legitimate purposes, such as network troubleshooting and security analysis.

Disclaimer
This program is provided for educational purposes and network analysis. Ensure that you have appropriate authorization and adhere to legal and ethical guidelines when using it on a network. Unauthorized packet capture or analysis may violate privacy and legal regulations.
