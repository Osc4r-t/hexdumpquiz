#!/usr/bin/env python3
"""
PANEL DE REFERENCIA DE CABECERAS
================================
Chuleta para tener abierta al lado mientras se resuelve un hex dump.

Muestra el formato de cada cabecera (Ethernet, ARP, IPv4, IPv6, ICMP, TCP,
UDP, DNS, DHCP), los offsets exactos de cada campo dentro de la trama, y las
tablas de valores que hacen falta para interpretar los bytes.

Uso:
    python3 referencia.py            panel completo e interactivo
    python3 referencia.py tcp        solo esa sección
    python3 referencia.py --lista    nombres de las secciones

Desde el juego: opción «Abrir el panel de referencia» del menú principal.
"""

import sys

A = "=" * 72
B = "-" * 72


# ---------------------------------------------------------------------------
# Secciones
# ---------------------------------------------------------------------------

TRAMA = """
DÓNDE EMPIEZA CADA COSA EN UNA TRAMA ETHERNET
{B}
  Offset absoluto en el volcado, para el caso más común (Ethernet + IPv4):

    0x0000  +--------------------------------------------------+
            |  Cabecera Ethernet ................... 14 bytes  |
    0x000e  +--------------------------------------------------+
            |  Cabecera IPv4 ....... 20 bytes (más si IHL > 5)  |
    0x0022  +--------------------------------------------------+
            |  Cabecera TCP (20+) / UDP (8) / ICMP (8)          |
    0x0036  +--------------------------------------------------+   TCP sin
            |  Datos de aplicación                              |   opciones
            +--------------------------------------------------+

  La regla de oro para no perderse:

    inicio de IP    = 14                        (siempre, en Ethernet)
    inicio de capa4 = 14 + IHL * 4              (IHL son los 4 bits bajos
                                                 del byte 0x0e)
    inicio de datos = 14 + IHL*4 + dataOffset*4 (en TCP)
                    = 14 + IHL*4 + 8            (en UDP e ICMP)

  Atajos que conviene memorizar (Ethernet + IPv4, IHL = 5):

    0x0000-0x0005   MAC destino          0x0016   TTL
    0x0006-0x000b   MAC origen           0x0017   Protocolo (6=TCP 17=UDP)
    0x000c-0x000d   EtherType            0x0018   Checksum IP
    0x000e          Versión + IHL        0x001a   IP origen
    0x0010          Longitud total       0x001e   IP destino
    0x0014          Flags + frag offset  0x0022   Puerto origen (capa 4)
                                         0x0024   Puerto destino
""".format(B=B)


ETHERNET = """
CABECERA ETHERNET II  -  14 bytes
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     MAC destino (6 bytes)                     |
  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                               |                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       MAC origen (6 bytes)    +
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          EtherType            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  offset  tamaño  campo
  0x0000    6     MAC destino     ff:ff:ff:ff:ff:ff = broadcast
  0x0006    6     MAC origen      los 3 primeros bytes son el OUI (fabricante)
  0x000c    2     EtherType       decide cómo leer lo que sigue

  EtherType      0x0800 IPv4    0x0806 ARP     0x86dd IPv6
                 0x8100 VLAN    0x8864 PPPoE   0x88cc LLDP
""".format(B=B)


ARP = """
ARP  -  28 bytes, empieza en 0x000e
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Hardware type          |        Protocol type          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  HW size      |  Proto size   |           Operation           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     MAC del emisor (6 bytes)                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      IP del emisor (4 bytes)                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    MAC del objetivo (6 bytes)                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     IP del objetivo (4 bytes)                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs     campo
  +0   0x000e  Hardware type   0x0001 = Ethernet
  +2   0x0010  Protocol type   0x0800 = resolviendo IPv4
  +4   0x0012  HW size         6 (tamaño de una MAC)
  +5   0x0013  Proto size      4 (tamaño de una IPv4)
  +6   0x0014  Operation       1 = request    2 = reply
  +8   0x0016  MAC emisor      quién dice ser el dueño
  +14  0x001c  IP emisor       la IP que reclama
  +18  0x0020  MAC objetivo    en un request va en ceros: es lo que se pregunta
  +24  0x0026  IP objetivo     la IP por la que se pregunta

  Señal de ARP spoofing: dos MAC distintas reclamando la misma IP, o una MAC
  reclamando varias IP, o replies que nadie pidió (gratuitous ARP).
""".format(B=B)


IPV4 = """
IPv4  -  20 bytes (más si IHL > 5), empieza en 0x000e
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Versión|  IHL  |     TOS       |         Longitud total        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Identification         |Flags|     Fragment Offset     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      TTL      |   Protocolo   |        Checksum cabecera      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        IP origen                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        IP destino                             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Opciones (solo si IHL > 5)                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs     campo
  +0   0x000e  Versión   4 bits ALTOS   0x45 >> 4 = 4
       0x000e  IHL       4 bits BAJOS   0x45 & 0x0f = 5  ->  5*4 = 20 bytes
  +1   0x000f  TOS/DSCP  calidad de servicio
  +2   0x0010  Long. total   cabecera IP + datos, SIN los 14 de Ethernet
  +4   0x0012  Identification  los fragmentos de un datagrama la comparten
  +6   0x0014  Flags     3 bits altos:  bit0 reservado
                                        bit1 DF = no fragmentar
                                        bit2 MF = vienen más fragmentos
  +6   0x0014  Frag offset   13 bits bajos, en unidades de 8 bytes
  +8   0x0016  TTL       64 Linux/macOS   128 Windows   255 equipos de red
  +9   0x0017  Protocolo 1=ICMP  6=TCP  17=UDP  58=ICMPv6
  +10  0x0018  Checksum  solo de la CABECERA; cada router lo recalcula
  +12  0x001a  IP origen     4 bytes, uno por número decimal
  +16  0x001e  IP destino    0xc0=192  0xa8=168  ->  c0 a8 .. .. es 192.168.x.x

  Cálculos:  cabecera IP    = IHL * 4
             datos de capa4 = Longitud total - IHL*4
             trama completa = Longitud total + 14
""".format(B=B)


IPV6 = """
IPv6  -  40 bytes fijos, empieza en 0x000e
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Versión| Traffic Class |             Flow Label                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Payload Length         |  Next Header  |   Hop Limit   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    IP origen (16 bytes)                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    IP destino (16 bytes)                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs     campo
  +0   0x000e  Versión       4 bits altos, vale 6
  +4   0x0012  Payload len   NO incluye los 40 bytes de cabecera
  +6   0x0014  Next header   mismo papel que «protocolo» en IPv4
  +7   0x0015  Hop limit     el TTL, con el nombre correcto
  +8   0x0016  IP origen     16 bytes
  +24  0x0026  IP destino    16 bytes

  Diferencias con IPv4 que se notan en el volcado:
    no hay IHL (la cabecera siempre mide 40), no hay checksum, y la longitud
    NO cuenta la cabecera propia. Capa 4 empieza siempre en 14 + 40 = 0x0036.
""".format(B=B)


ICMP = """
ICMP  -  8 bytes de cabecera
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      Tipo     |    Código     |            Checksum           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Identifier            |        Sequence number        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Datos / paquete original                  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Tipos:   0  Echo Reply              8  Echo Request
           3  Destination Unreachable 11 Time Exceeded (TTL agotado)
           5  Redirect                12 Parameter Problem

  Códigos cuando el tipo es 3 (destino inalcanzable):
           0 red inalcanzable       3 puerto inalcanzable
           1 host inalcanzable      4 hace falta fragmentar pero DF está activo
           2 protocolo inalcanzable 13 prohibido por firewall

  En Echo Request/Reply, identifier y sequence emparejan la ida con la vuelta:
  la respuesta repite exactamente los mismos dos valores.

  En un mensaje de error (tipo 3 u 11), después de los 8 bytes viene copiada la
  cabecera IP del paquete que falló más sus 8 primeros bytes: por eso el origen
  puede saber qué conexión concreta se rompió.
""".format(B=B)


TCP = """
TCP  -  20 bytes (más si data offset > 5)
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Puerto origen        |        Puerto destino         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Sequence number                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Acknowledgment number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Offset|  Rsv  |     Flags     |            Window             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |        Urgent pointer         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Opciones (solo si data offset > 5)              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs*    campo
  +0   0x0022  Puerto origen
  +2   0x0024  Puerto destino
  +4   0x0026  Sequence number   TCP numera BYTES, no paquetes
  +8   0x002a  Acknowledgment    el SIGUIENTE byte esperado (acumulativo)
  +12  0x002e  Data offset       4 bits ALTOS  ->  cabecera = offset * 4
  +13  0x002f  Flags             un byte, un bit por flag
  +14  0x0030  Window            ventana de recepción (rwnd), control de flujo
  +16  0x0032  Checksum          cubre cabecera + datos + IPs (pseudocabecera)
  +18  0x0034  Urgent pointer    solo válido si URG está activa
       (* offsets absolutos con Ethernet + IPv4 con IHL = 5)

  FLAGS: el byte 0x2f, bit a bit

     0x01 FIN   cierre ordenado de esta mitad de la conexión
     0x02 SYN   apertura, sincroniza números de secuencia
     0x04 RST   corte abrupto (puerto cerrado o conexión inválida)
     0x08 PSH   entrega estos datos a la aplicación ya
     0x10 ACK   el campo acknowledgment es válido
     0x20 URG   hay datos urgentes
     0x40 ECE   notificación de congestión
     0x80 CWR   se redujo la ventana por congestión

     Combinaciones frecuentes:
       0x02 = SYN        primer paquete del handshake
       0x12 = SYN+ACK    respuesta del servidor
       0x10 = ACK        confirmación
       0x18 = PSH+ACK    datos con confirmación
       0x11 = FIN+ACK    cierre
       0x04 = RST        rechazo
       0x14 = RST+ACK    rechazo con confirmación

  OPCIONES (kind, length, valor):
       kind 0  fin de la lista        kind 3  Window Scale (factor s)
       kind 1  NOP, relleno           kind 4  SACK permitted
       kind 2  MSS                    kind 8  Timestamps

  Cálculos:  cabecera TCP  = dataOffset * 4
             datos         = LongTotalIP - IHL*4 - dataOffset*4
             ventana real  = Window * 2^s   (si se negoció Window Scale)
""".format(B=B)


UDP = """
UDP  -  8 bytes de cabecera
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Puerto origen        |        Puerto destino         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |            Longitud           |            Checksum           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  abs*    campo
  +0   0x0022  Puerto origen
  +2   0x0024  Puerto destino
  +4   0x0026  Longitud     INCLUYE los 8 bytes de cabecera -> datos = long - 8
  +6   0x0028  Checksum     opcional en IPv4 (0x0000 = sin checksum),
                            obligatorio en IPv6

  Cuidado con las tres longitudes, que se cuentan distinto:
     IPv4 longitud total  -> SÍ incluye su propia cabecera
     IPv6 payload length  -> NO incluye su propia cabecera
     UDP  longitud        -> SÍ incluye su propia cabecera
""".format(B=B)


DNS = """
DNS  -  12 bytes de cabecera, sobre UDP puerto 53
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Transaction ID         |             Flags             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           QDCOUNT             |            ANCOUNT            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           NSCOUNT             |            ARCOUNT            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Question: QNAME (longitud variable), QTYPE, QCLASS        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  rel  campo
  +0   Transaction ID  empareja consulta y respuesta. Acertarlo (junto con el
                       puerto origen) es lo que permite el DNS spoofing.
  +2   Flags           bit 15 QR   0 = consulta, 1 = respuesta
                       bits 11-14  opcode
                       bit 10 AA   respuesta autoritativa
                       bit 9  TC   truncada (hay que reintentar por TCP)
                       bit 8  RD   recursión deseada
                       bit 7  RA   recursión disponible
                       bits 0-3    rcode
  +4   QDCOUNT         número de preguntas
  +6   ANCOUNT         número de respuestas (0 en una consulta)
  +8   NSCOUNT / +10 ARCOUNT

  EL NOMBRE NO LLEVA PUNTOS EN EL VOLCADO. Se codifica como etiquetas
  «longitud + texto», terminadas en 00:

     07 65 78 61 6d 70 6c 65  03 63 6f 6d  00
      7  e  x  a  m  p  l  e   3  c  o  m  fin      ->  example.com

  Un byte cuyos dos bits altos son 11 (0xc0) NO es una longitud: es un puntero
  de compresión al offset indicado por los 14 bits restantes.

  QTYPE:   1 A       5 CNAME    15 MX     28 AAAA    255 ANY
           2 NS      6 SOA      12 PTR    16 TXT      33 SRV
  QCLASS:  1 IN (Internet), prácticamente siempre.
  RCODE:   0 NOERROR  2 SERVFAIL  3 NXDOMAIN  5 REFUSED
""".format(B=B)


DHCP = """
DHCP / BOOTP  -  236 bytes fijos + opciones, sobre UDP 67/68
{B}
  rel   tamaño  campo
  +0      1     op          1 = petición del cliente, 2 = respuesta del servidor
  +1      1     htype       1 = Ethernet
  +2      1     hlen        6
  +4      4     xid         transaction id, común a los 4 mensajes del ciclo
  +12     4     ciaddr      IP que el cliente YA tenía (0.0.0.0 en un Discover)
  +16     4     yiaddr      «your IP»: la IP que el servidor ASIGNA
  +20     4     siaddr      IP del servidor
  +28     16    chaddr      MAC del cliente (el servidor lo identifica por aquí)
  +236    4     magic       siempre 63 82 53 63
  +240    ...   opciones    kind + length + valor

  Opción 53 = tipo de mensaje:
       1 Discover   cliente -> broadcast, «¿hay algún servidor DHCP?»
       2 Offer      servidor -> cliente, «te ofrezco esta IP»
       3 Request    cliente -> broadcast, «acepto esa IP»
       5 ACK        servidor -> cliente, «confirmada»
       6 NAK   7 Release   8 Inform

  El ciclo DORA es Discover, Offer, Request, ACK. Un Discover sale de 0.0.0.0
  hacia 255.255.255.255 porque el cliente todavía no tiene dirección.

  DHCP spoofing: un servidor falso que conteste antes que el legítimo se queda
  como gateway y DNS de la víctima.
""".format(B=B)


TABLAS = """
TABLAS DE VALORES
{B}
  EtherType (0x000c)          Protocolo IP (0x0017)
    0x0800  IPv4                 1   ICMP        50  ESP
    0x0806  ARP                  2   IGMP        51  AH
    0x86dd  IPv6                 6   TCP         58  ICMPv6
    0x8100  VLAN 802.1Q         17   UDP         89  OSPF
    0x8864  PPPoE               47   GRE        132  SCTP

  Puertos bien conocidos
    20/21 FTP       53  DNS       143 IMAP      3306 MySQL
    22    SSH       67  DHCP srv  161 SNMP      3389 RDP
    23    Telnet    68  DHCP cli  179 BGP       5353 mDNS
    25    SMTP      80  HTTP      443 HTTPS     8080 HTTP alt
    69    TFTP     110  POP3      445 SMB        123 NTP

  TTL inicial típico          ICMP tipo
    64   Linux, macOS           0  Echo Reply      8  Echo Request
    128  Windows                3  Unreachable    11 Time Exceeded
    255  routers, switches      5  Redirect       12 Parameter Problem

  ASCII útil en la columna de la derecha del volcado
    0x0d 0x0a  CR LF (fin de línea en HTTP, FTP, SMTP)
    0x20       espacio        0x30-0x39  dígitos 0-9
    0x41-0x5a  A-Z            0x61-0x7a  a-z
    Fuera de 0x20-0x7e el volcado muestra un punto.

  Hexadecimal que aparece todo el rato
    0x45 = 0100 0101  ->  versión 4, IHL 5   (arranque de casi todo IPv4)
    0xc0 = 192   0xa8 = 168   0x0a = 10      (redes privadas)
    0xff = 255   0x00 = 0
    0x0050 = 80 (HTTP)   0x01bb = 443 (HTTPS)   0x0035 = 53 (DNS)
""".format(B=B)


VENTANA = """
VENTANA DESLIZANTE, GO-BACK-N Y SELECTIVE REPEAT
{B}
                        Go-Back-N            Selective Repeat
  Receptor fuera de     descarta             guarda en buffer
  orden
  Tipo de ACK           acumulativo          individual
  Temporizadores        uno (el más antiguo) uno por paquete en vuelo
  Al perderse uno       reenvía ese y todos  reenvía solo el perdido
                        los posteriores
  Ventana máxima        2^k - 1              2^(k-1)
  Coste                 ancho de banda       memoria y complejidad

  Stop-and-wait es el caso N = 1.
  TCP es un híbrido: ACK acumulativo como GBN, pero el receptor bufferiza lo
  que llega fuera de orden y con SACK confirma bloques sueltos, como SR.

  Fórmulas
    retransmisiones GBN  = último - perdido + 1
    retransmisiones SR   = 1
    BDP (bytes)          = ancho de banda x RTT / 8
    ventana real TCP     = campo Window x 2^s
    bytes en vuelo       = min(cwnd, rwnd)

  En el volcado solo se ve rwnd (campo Window, 2 bytes en 0x0030). La ventana
  de congestión cwnd es una variable interna del emisor: nunca se transmite.

  win = 0  ->  buffer del receptor lleno: el emisor para y manda window probes.
""".format(B=B)


SECCIONES = [
    ("trama",     "Offsets dentro de la trama",       TRAMA),
    ("ethernet",  "Cabecera Ethernet II",             ETHERNET),
    ("arp",       "ARP",                              ARP),
    ("ipv4",      "IPv4",                             IPV4),
    ("ipv6",      "IPv6",                             IPV6),
    ("icmp",      "ICMP",                             ICMP),
    ("tcp",       "TCP y sus flags",                  TCP),
    ("udp",       "UDP",                              UDP),
    ("dns",       "DNS",                              DNS),
    ("dhcp",      "DHCP / BOOTP",                     DHCP),
    ("tablas",    "Tablas de valores y ASCII",        TABLAS),
    ("ventana",   "Ventana deslizante, GBN y SR",     VENTANA),
]


# ---------------------------------------------------------------------------
# Presentación
# ---------------------------------------------------------------------------

def cabecera() -> None:
    print(A)
    print("  PANEL DE REFERENCIA DE CABECERAS")
    print(A)


def mostrar(clave: str) -> bool:
    for nombre, _, texto in SECCIONES:
        if nombre == clave:
            print(texto)
            return True
    return False


def mostrar_todo() -> None:
    cabecera()
    for _, _, texto in SECCIONES:
        print(texto)


def indice() -> None:
    print("\n" + B)
    print("  Secciones:  " + "  ".join(n for n, _, _ in SECCIONES))
    print("  Escribe un nombre para verla sola, «todo» para el panel completo,")
    print("  «l» para este índice, o «q» para cerrar la ventana.")
    print(B)


def interactivo() -> None:
    mostrar_todo()
    indice()
    while True:
        try:
            orden = input("\nreferencia> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return
        if orden in ("q", "salir", "exit"):
            return
        if orden in ("", "l", "lista", "?"):
            indice()
            continue
        if orden in ("todo", "all"):
            mostrar_todo()
            indice()
            continue
        if not mostrar(orden):
            coincidencias = [n for n, _, _ in SECCIONES if n.startswith(orden)]
            if len(coincidencias) == 1:
                mostrar(coincidencias[0])
            else:
                print(f"No conozco «{orden}». Secciones: "
                      + ", ".join(n for n, _, _ in SECCIONES))


def main() -> None:
    args = [a.lower() for a in sys.argv[1:]]
    if not args:
        interactivo()
        return
    if args[0] in ("--lista", "-l", "--list"):
        for nombre, desc, _ in SECCIONES:
            print(f"  {nombre:<10} {desc}")
        return
    cabecera()
    for a in args:
        if not mostrar(a):
            print(f"  No conozco la sección «{a}».")


if __name__ == "__main__":
    main()
