# PacketSniffer-Pcap



PacketSniffer-Pcap is a powerful C program designed to capture and analyze network packets using the pcap library. It specializes in filtering and examining HTTP (Hypertext Transfer Protocol) packets, providing valuable insights into network traffic. This tool extracts essential details from HTTP packets, including Ethernet and IP addresses, source and destination ports, and the HTTP payload data.

## Prerequisites

Before diving into packet sniffing, ensure you have the following prerequisites installed:

- **libpcap**: This indispensable library empowers the program to capture network packets. For Linux users, you can effortlessly install it using the package manager:

```bash
sudo apt-get install libpcap-dev
```
# Usage
Let's get started with PacketSniffer-Pcap in just a few simple steps:

## Compile the Program
First, compile the program using a C compiler like GCC:
# Compile the program
```bash

gcc -o packet_sniffer packet_sniffer.c -lpcap
```
# Replace 'packet_sniffer' with your desired executable name
## Run the Program
Execute the compiled program with the following command:

```bash

./packet_sniffer [protocol] [number-of-packets]
[protocol]: Specify the protocol you want to filter (e.g., "tcp", "udp").
[number-of-packets]: Define the number of packets you wish to capture.
Select a Network Interface
```
The program will present a list of available network interfaces. Choose the desired interface for packet capture when prompted.

## Start Packet Capture
PacketSniffer-Pcap will commence capturing packets on the selected interface, based on the specified protocol and packet count.

## View Captured Data
As packets flow in, the program will elegantly display essential information, including Ethernet source and destination MAC addresses, source and destination IP addresses, source and destination ports, and the HTTP payload data.

## Extract Credentials and Cookies
PacketSniffer-Pcap goes the extra mile by attempting to extract and display any usernames (uname), passwords (pass), or cookies (Cookie:) found within the HTTP payload data.

## Finish
To gracefully halt the packet capture, simply press Ctrl+C. The program will courteously bid farewell with a "Done with packet sniffing!" message before exiting.

## Example
Here's a quick example of how to use the program to capture TCP packets on interface eth0:

bash
Copy code
./packet_sniffer tcp 10
This command will capture the first 10 TCP packets on eth0, providing detailed packet information and extracting credentials and cookies when present in the HTTP payload data.

## Notes
While PacketSniffer-Pcap primarily focuses on HTTP packets, you have the freedom to modify it to capture and analyze packets of other protocols. Simply adjust the protocol argument in the command line.

Ensure that you possess the necessary permissions to capture packets on the selected network interface. Superuser (root) privileges or appropriate permissions may be required.

The program leverages the libpcap library for efficient packet capture and network interface management.

Always exercise caution when working with packet capture tools, as they have the potential to access sensitive information. Use them responsibly and solely for legitimate purposes such as network troubleshooting and security analysis.

Disclaimer
PacketSniffer-Pcap is provided exclusively for educational purposes and network analysis. Prior to usage, make sure to obtain the appropriate authorization and adhere to legal and ethical guidelines when deploying it on a network. Unauthorized packet capture or analysis may infringe on privacy and legal regulations.
