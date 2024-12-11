# ARP Spoofer 🕵️‍♂️

## Overview
The ARP Spoofer is a Python script designed to perform ARP spoofing on a specified IP range. It allows you to intercept and manipulate network traffic between devices on a local network. This tool is intended for educational purposes and should only be used in environments where you have permission to test network security.

## Features
- Conducts an ARP scan to identify devices on the network.
- Allows you to select a target device for ARP spoofing.
- Continuously sends spoofed ARP packets to the target device.
- Captures packets and saves them to a `.pcap` file for analysis.

## Requirements 📦

To run this script, you need the following libraries:
- `scapy`: A powerful Python library for network packet manipulation.
- `ipaddress`: A built-in Python library for creating and manipulating IP addresses and networks.

You can install the required libraries using pip:

```bash
pip install scapy
```

### Usage 🚀

1. Run the script with sudo privileges to ensure it has the necessary permissions to manipulate network settings:

```bash
sudo python3 arp_spoofer.py -ip_range <ip_range>
```
Replace <ip_range> with the desired IP range (e.g., 192.168.1.0/24).

2. **Select the target** device from the displayed list of devices on the network. Enter the corresponding ID to start the ARP spoofing process.
3. **Monitor the captured packets** in the **`requests.pcap`** file generated in the current working directory.
```bash
sudo python3 arp_spoofer.py -ip_range 192.168.1.0/24
```

### Important Notes ⚠️
- **Ethical Use**: This tool should only be used in a controlled environment where you have explicit permission to test network security.
- **Network Disruption**: ARP spoofing can disrupt network communication. Use with caution and be aware of the potential impact on the network.

### License 📄

This project is licensed under the MIT License. See the LICENSE file for details.

### Contributing 🤝

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.
