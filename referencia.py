#!/usr/bin/env python3
"""
HEADER REFERENCE PANEL
======================
A cheat sheet to keep open beside you while you work through a hex dump.

It has two halves:

  · The layout of every header (Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP,
    DNS, DHCP, RIP, OSPF) with the exact offset of each field, plus the value
    tables you need to interpret the bytes.

  · The theory as a formulary: what RIP does, what OSPF does, and the rules of
    Go-Back-N, Selective Repeat and real TCP, laid out as "on this event, this
    is what you do".

Usage:
    python3 referencia.py            full interactive panel
    python3 referencia.py tcp        one section only
    python3 referencia.py --list     section names

From the game: the "Open the reference guide in a window" menu option, or type
«form» while answering a question.
"""

import sys

A = "=" * 72
B = "-" * 72


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

FRAME = """
WHERE EVERYTHING STARTS INSIDE AN ETHERNET FRAME
{B}
  Absolute offset in the dump, for the most common case (Ethernet + IPv4):

    0x0000  +--------------------------------------------------+
            |  Ethernet header ..................... 14 bytes  |
    0x000e  +--------------------------------------------------+
            |  IPv4 header ......... 20 bytes (more if IHL > 5) |
    0x0022  +--------------------------------------------------+
            |  TCP (20+) / UDP (8) / ICMP (8) header            |
    0x0036  +--------------------------------------------------+   TCP with
            |  Application data                                 |   no options
            +--------------------------------------------------+

  The golden rule so you never get lost:

    start of IP      = 14                        (always, on Ethernet)
    start of layer 4 = 14 + IHL * 4              (IHL is the low nibble of
                                                  the byte at 0x0e)
    start of data    = 14 + IHL*4 + dataOffset*4 (TCP)
                     = 14 + IHL*4 + 8            (UDP and ICMP)

  Shortcuts worth memorising (Ethernet + IPv4, IHL = 5):

    0x0000-0x0005   destination MAC      0x0016   TTL
    0x0006-0x000b   source MAC           0x0017   Protocol (6=TCP 17=UDP)
    0x000c-0x000d   EtherType            0x0018   IP checksum
    0x000e          Version + IHL        0x001a   source IP
    0x0010          Total length         0x001e   destination IP
    0x0014          Flags + frag offset  0x0022   source port (layer 4)
                                         0x0024   destination port
""".format(B=B)


ETHERNET = """
ETHERNET II HEADER  -  14 bytes
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Destination MAC (6 bytes)                    |
  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                               |                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       Source MAC (6 bytes)    +
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          EtherType            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  offset  size  field
  0x0000    6   Destination MAC   ff:ff:ff:ff:ff:ff = broadcast
  0x0006    6   Source MAC        the first 3 bytes are the OUI (vendor)
  0x000c    2   EtherType         decides how to read what follows

  EtherType      0x0800 IPv4    0x0806 ARP     0x86dd IPv6
                 0x8100 VLAN    0x8864 PPPoE   0x88cc LLDP
""".format(B=B)


ARP = """
ARP  -  28 bytes, starts at 0x000e
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Hardware type          |        Protocol type          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  HW size      |  Proto size   |           Operation           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Sender MAC (6 bytes)                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Sender IP (4 bytes)                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Target MAC (6 bytes)                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Target IP (4 bytes)                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs     field
  +0   0x000e  Hardware type   0x0001 = Ethernet
  +2   0x0010  Protocol type   0x0800 = resolving IPv4
  +4   0x0012  HW size         6 (the size of a MAC)
  +5   0x0013  Proto size      4 (the size of an IPv4 address)
  +6   0x0014  Operation       1 = request    2 = reply
  +8   0x0016  Sender MAC      who claims to be the owner
  +14  0x001c  Sender IP       the address being claimed
  +18  0x0020  Target MAC      all zeros in a request: that is what is asked
  +24  0x0026  Target IP       the address being asked about

  Sign of ARP spoofing: two different MACs claiming the same IP, or one MAC
  claiming several IPs, or replies nobody asked for (gratuitous ARP).
""".format(B=B)


IPV4 = """
IPv4  -  20 bytes (more if IHL > 5), starts at 0x000e
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Version|  IHL  |      TOS      |         Total length          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Identification         |Flags|     Fragment Offset     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      TTL      |   Protocol    |        Header checksum        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Source IP                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Destination IP                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   Options (only if IHL > 5)                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs     field
  +0   0x000e  Version   HIGH nibble    0x45 >> 4 = 4
       0x000e  IHL       LOW nibble     0x45 & 0x0f = 5  ->  5*4 = 20 bytes
  +1   0x000f  TOS/DSCP  quality of service
  +2   0x0010  Total len IP header + data, NOT the 14 Ethernet bytes
  +4   0x0012  Identification  all fragments of one datagram share it
  +6   0x0014  Flags     3 high bits:  bit0 reserved
                                       bit1 DF = do not fragment
                                       bit2 MF = more fragments coming
  +6   0x0014  Frag offset   13 low bits, counted in units of 8 bytes
  +8   0x0016  TTL       64 Linux/macOS   128 Windows   255 network gear
  +9   0x0017  Protocol  1=ICMP  6=TCP  17=UDP  58=ICMPv6  89=OSPF
  +10  0x0018  Checksum  covers the HEADER only; every router recomputes it
  +12  0x001a  Source IP       4 bytes, one per decimal number
  +16  0x001e  Destination IP  0xc0=192  0xa8=168  ->  c0 a8 .. .. is 192.168.x.x

  Arithmetic:  IP header    = IHL * 4
               layer 4 data = Total length - IHL*4
               whole frame  = Total length + 14
""".format(B=B)


IPV6 = """
IPv6  -  40 fixed bytes, starts at 0x000e
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Version| Traffic Class |             Flow Label                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Payload Length         |  Next Header  |   Hop Limit   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Source IP (16 bytes)                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Destination IP (16 bytes)                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs     field
  +0   0x000e  Version       high nibble, always 6
  +4   0x0012  Payload len   does NOT include the 40-byte header
  +6   0x0014  Next header   same role as "protocol" in IPv4
  +7   0x0015  Hop limit     the TTL, under the name it should always have had
  +8   0x0016  Source IP     16 bytes
  +24  0x0026  Destination   16 bytes

  Differences from IPv4 you can spot in the dump:
    no IHL (the header is always 40), no checksum, and the length does NOT
    count its own header. Layer 4 always starts at 14 + 40 = 0x0036.
""".format(B=B)


ICMP = """
ICMP  -  8-byte header
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      Type     |     Code      |            Checksum           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Identifier            |        Sequence number        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Data / original packet                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Types:   0  Echo Reply              8  Echo Request
           3  Destination Unreachable 11 Time Exceeded (TTL expired)
           5  Redirect                12 Parameter Problem

  Codes when the type is 3 (destination unreachable):
           0 network unreachable    3 port unreachable
           1 host unreachable       4 fragmentation needed but DF is set
           2 protocol unreachable  13 administratively prohibited (firewall)

  In Echo Request/Reply, identifier and sequence pair the outbound packet with
  its answer: the reply repeats exactly the same two values.

  In an error message (type 3 or 11), after the 8 bytes comes a copy of the IP
  header of the packet that failed plus its first 8 bytes: that is how the
  sender can tell which connection broke.
""".format(B=B)
