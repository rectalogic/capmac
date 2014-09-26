import sys
import os
import subprocess
from itertools import cycle
import argparse
import plistlib
import scapy.all as scapy

# broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast
IGNORE_MAC = ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:')

AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
TCPDUMP = "/usr/sbin/tcpdump"

CHANNEL_HOP = 100

TYPE_CONTROL = 1
TYPE_DATA = 2
CONTROL_BLOCK_ACK = 9
CONTROL_RTS = 11
CONTROL_CTS = 12
CONTROL_SUBTYPES = (CONTROL_BLOCK_ACK, CONTROL_RTS, CONTROL_CTS)


class MACCollector(object):
    def __init__(self, channels, bssids, interface):
        self.clients = set()
        self.bssids = bssids
        self.channels = cycle(channels)
        self.interface = interface
        self.fifo = os.path.join(os.path.dirname(__file__), "pcapfifo.cap")
        if not os.path.exists(self.fifo):
            os.mkfifo(self.fifo)

    def start(self):
        subprocess.check_call([AIRPORT, "--disassociate"])
        self.hop_channel()

        subprocess.Popen([TCPDUMP, "-I", "-n", "-i", self.interface, "-w", self.fifo])

        pcap = scapy.PcapReader(self.fifo)
        for packet in pcap:
            self.process_packet(packet)

    def hop_channel(self):
        channel = self.channels.next()
        subprocess.check_call([AIRPORT, u"--channel={0}".format(channel)])
        self.channel_hop_count = CHANNEL_HOP

    def process_packet(self, packet):
        if packet.haslayer(scapy.Dot11):
            if (
                    (packet.type == TYPE_CONTROL and packet.subtype in CONTROL_SUBTYPES) or
                    packet.haslayer(scapy.Dot11AssoReq) or packet.haslayer(scapy.Dot11AssoResp) or
                    packet.haslayer(scapy.Dot11ReassoReq) or packet.haslayer(scapy.Dot11ReassoResp) or
                    packet.haslayer(scapy.Dot11Disas)):

                addr1 = packet.addr1.lower() if packet.addr1 else ""
                addr2 = packet.addr2.lower() if packet.addr2 else ""

                for ignore in IGNORE_MAC:
                    if addr2.startswith(ignore) or addr1.startswith(ignore):
                        return

                # print(packet.summary())

                if addr1 in self.bssids and addr2 not in self.bssids:
                    addr = addr2
                elif addr2 in self.bssids and addr1 not in self.bssids:
                    addr = addr1
                else:
                    return
                if not addr:
                    return

                if addr not in self.clients:
                    print addr
                    self.clients.add(addr)

            self.channel_hop_count -= 1
            if self.channel_hop_count <= 0:
                self.hop_channel()


def scan_ssid(ssid):
    """Return tuple with set of all channels and all BSSIDs"""
    result = subprocess.check_output([AIRPORT, u"--scan={0}".format(ssid), "--xml"])
    plist = plistlib.readPlistFromString(result)
    bssids = set()
    channels = set()
    for station in plist:
        channels.add(station["CHANNEL"])
        bssid = ":".join(u"{0:02x}".format(int(octet, 16)) for octet in station["BSSID"].split(":"))
        bssids.add(bssid)
    return channels, bssids


def main():
    parser = argparse.ArgumentParser(description="Capture WiFi client MAC addresses for a given SSID")
    parser.add_argument('-i', '--interface', default="en0", help="Network interface to sniff")
    parser.add_argument('-s', '--ssid', help="Scan all BSSID MAC addresses and channels associated with SSID")
    args = parser.parse_args()

    if not args.ssid:
        parser.print_help()
        sys.exit(1)

    channels, bssids = scan_ssid(args.ssid)
    if not bssids:
        print("No BSSIDs found")
        sys.exit(1)

    collector = MACCollector(channels, bssids, args.interface)
    try:
        collector.start()
    except KeyboardInterrupt:
        print("Collected MAC addresses:")
        for client in collector.clients:
            print(client)


if __name__ == "__main__":
    main()
