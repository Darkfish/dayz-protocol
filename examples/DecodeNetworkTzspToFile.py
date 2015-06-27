from scapy.all import *
from net import protocol
from time import time


def readp(packet):
    """Read network data stream from Mikrotik router (TZSP format)"""
    timestamp = time()
    udp_packet = packet.payload.payload
    tzsp_packet = udp_packet.payload
    tzsp_packet_str = str(tzsp_packet)

    #: Use terrible hack to get rid of TZSP header
    tzsp_minus_header_str = tzsp_packet_str[5:]

    #: Let's be lazy and let scapy make sense of this again
    try:
        tzsp_decapsulated_packet = Ether(tzsp_minus_header_str)
    except:
        return

    #: Find SRC ip
    if IP in tzsp_decapsulated_packet:
        ip_src = tzsp_decapsulated_packet[IP].src
        ip_dst = tzsp_decapsulated_packet[IP].dst

        #: Extract Ethernet -> IP -> UDP payload from packet
        udp_payload = tzsp_decapsulated_packet.payload.payload.payload

        #: Write raw packet to file
        with open("./Packets/{0}-{1}-{2}.packet".format(
            timestamp,
            ip_src,
            ip_dst
        ), 'wb') as f:
            f.write(str(udp_payload))

        #: Is this packet large enough to be valid?
        if len(str(udp_payload)) > 24:
            dayzp = protocol.packet(str(udp_payload))

            #: Write decoded packet to file
            with open("./Packets/{0}-{1}-{2}.packet.decoded".format(
                timestamp,
                ip_src,
                ip_dst
            ), 'wb') as f:
                f.write(dayzp.payload.data)


def main():
    sniff(iface="eth0", filter="udp and port 37008", prn=readp)

main()
