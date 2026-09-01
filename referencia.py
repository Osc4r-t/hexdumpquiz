#!/usr/bin/env python3
"""
PANEL DE REFERENCIA DE CABECERAS
================================
Chuleta para tener abierta al lado mientras se resuelve un hex dump.

Tiene dos mitades:

  · El formato de cada cabecera (Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP,
    DNS, DHCP, RIP, OSPF) con los offsets exactos de cada campo, y las tablas
    de valores que hacen falta para interpretar los bytes.

  · La teoría en forma de formulario: qué hace RIP, qué hace OSPF, y las
    reglas de actuación de Go-Back-N, Selective Repeat y del TCP real, con el
    esquema «ante este evento, esto es lo que hay que hacer».

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



TEORIA_RIP = """
RIP  ·  TEORÍA Y REGLAS DE ACTUACIÓN
{B}
  QUÉ ES
    Protocolo de VECTOR DISTANCIA (algoritmo de Bellman-Ford distribuido).
    Cada router NO conoce la topología: solo sabe, para cada red, a qué vecino
    hay que mandarle el paquete y a cuántos saltos está. Esa información la
    aprende de lo que le cuentan sus vecinos, y se la cree.

    «Le digo a mis vecinos lo que sé; ellos le suman 1 y lo reenvían.»

  DATOS BÁSICOS
    Métrica         número de saltos (routers atravesados)
    Máximo          15 saltos.  16 = INFINITO = inalcanzable
    Transporte      UDP, puerto 520 (RIPng: UDP 521)
    Destino         RIPv2: multicast 224.0.0.9   ·   RIPv1: broadcast
    TTL             1, para que no salga de la LAN
    Versiones       v1 classful (sin máscara) · v2 con máscara, multicast y
                    autenticación · RIPng para IPv6

  TEMPORIZADORES (los cuatro que hay que saber)
    Update       30 s   cada cuánto se manda la tabla entera a los vecinos
    Invalid     180 s   sin noticias de una ruta -> se marca con métrica 16
    Holddown    180 s   tras marcarla, se ignoran rutas peores para esa red
    Flush       240 s   se borra definitivamente de la tabla

  QUÉ HACE EL ROUTER EN CADA CASO
    Evento                          Acción según la teoría
    ------------------------------  ------------------------------------------
    Arranca                         manda un Request pidiendo la tabla entera
                                    (AFI=0, métrica=16) a 224.0.0.9
    Recibe un Request               responde con su tabla completa
    Cada 30 segundos                manda un Response con TODA su tabla
    Recibe una ruta a la red R      coste = métrica recibida + 1
    con métrica m de un vecino V    · si no tenía la red -> la instala
                                    · si coste < el actual -> la sustituye
                                    · si viene del MISMO vecino del que
                                      ya la aprendió -> la actualiza
                                      aunque empeore
                                    · si coste >= 16 -> inalcanzable
                                    y en todos los casos reinicia el timer
    Pasan 180 s sin refrescar       marca la ruta con métrica 16 y avisa
    Pasan 240 s                     borra la ruta de la tabla
    Se cae un enlace suyo           TRIGGERED UPDATE: anuncia métrica 16 al
                                    instante, sin esperar a los 30 s

  EL PROBLEMA: CUENTA A INFINITO
    A --- B --- C.  Se cae la red de C.
    B lo sabe, pero antes de avisar recibe de A: «yo llego a C en 2 saltos».
    B se lo cree y anuncia 3; A entonces anuncia 4; y así hasta 16.
    El bucle se resuelve solo, pero lentamente. Por eso existen:

    Split horizon        no anunciar una ruta por la misma interfaz por la que
                         la aprendiste
    Poison reverse       en vez de callarla, anunciarla con métrica 16
    Triggered update     avisar del cambio al instante, sin esperar el ciclo
    Holddown             tras una mala noticia, desconfiar de las rutas nuevas
                         a esa red durante un rato

  CÓMO SE VE EN EL VOLCADO
    IP protocolo 17 (UDP), puertos 520 -> 520, destino 224.0.0.9, TTL 1.
    Cabecera de 4 bytes: comando (1=Request, 2=Response), versión, 2 en cero.
    Después, entradas de 20 bytes exactos:
      AFI(2) · route tag(2) · red(4) · máscara(4) · next hop(4) · métrica(4)
    Nº de rutas = (longitud UDP - 8 - 4) / 20
""".format(B=B)


TEORIA_OSPF = """
OSPF  ·  TEORÍA Y REGLAS DE ACTUACIÓN
{B}
  QUÉ ES
    Protocolo de ESTADO DE ENLACE. Al revés que RIP: cada router averigua la
    topología COMPLETA de su área, se construye un mapa idéntico al de sus
    compañeros, y calcula por su cuenta el camino más corto con Dijkstra.

    «No me creo lo que me cuentan: me dan el mapa y yo calculo la ruta.»

  DATOS BÁSICOS
    Transporte      directamente sobre IP, protocolo 89 (no hay puertos)
    Destinos        224.0.0.5 todos los routers OSPF
                    224.0.0.6 solo el DR y el BDR
    TTL             1
    Métrica         coste = ancho de banda de referencia / ancho de banda
                    (por defecto 100 Mbps de referencia; el coste mínimo es 1)
    Áreas           el área 0.0.0.0 es el backbone; todas las demás cuelgan
                    de ella
    Router ID       32 bits con forma de IP. Se elige: el configurado a mano,
                    si no la IP más alta de una loopback, si no la más alta
                    de una interfaz activa

  LAS TRES TABLAS QUE MANTIENE
    Vecinos      con quién habla y en qué estado está cada adyacencia
    Topología    la LSDB: el mapa. Es IDÉNTICA en todos los routers del área
    Enrutamiento el resultado de correr Dijkstra sobre la LSDB

  LOS CINCO TIPOS DE PAQUETE
    1  Hello    descubre vecinos y mantiene viva la adyacencia
    2  DBD      resumen de «esto es lo que tengo en mi base de datos»
    3  LSR      «de eso, mándame lo que me falta»
    4  LSU      aquí van las LSA de verdad
    5  LSAck    confirma la recepción (OSPF es fiable por su cuenta)

  ESTADOS POR LOS QUE PASA UNA ADYACENCIA
    Down      -> no se ha oído nada
    Init      -> he recibido un Hello suyo, pero él aún no me nombra
    2-Way     -> me veo en SU lista de vecinos: la comunicación es bidireccional
                 (aquí se eligen DR y BDR)
    ExStart   -> negocian quién empieza el intercambio
    Exchange  -> se mandan los DBD
    Loading   -> se piden con LSR lo que falta
    Full      -> las dos bases de datos son idénticas. Objetivo alcanzado

  PARA QUE DOS ROUTERS LLEGUEN A SER VECINOS DEBEN COINCIDIR EN
    · el Area ID
    · el Hello interval y el Dead interval
    · la máscara de la red
    · el tipo de autenticación y su clave
    · la MTU
    · las banderas de área (stub, NSSA)
    Si falla UNA sola, la adyacencia no se forma. Es el primer sitio donde
    mirar cuando «OSPF no levanta».

  ELECCIÓN DEL DR Y EL BDR
    Por qué       en una red con N routers habría N(N-1)/2 adyacencias. Con un
                  DR que centralice, son solo N.
    Dónde         solo en redes de acceso múltiple (Ethernet). En un enlace
                  punto a punto (una /30) NO hace falta: DR = 0.0.0.0
    Cómo          gana la PRIORIDAD más alta;  si empatan, el ROUTER ID mayor
                  prioridad 0 = renuncia a ser DR
    Ojo           la elección NO es apropiativa: si aparece después un router
                  con más prioridad, NO desbanca al DR actual

  QUÉ HACE EL ROUTER EN CADA CASO
    Evento                          Acción según la teoría
    ------------------------------  ------------------------------------------
    Arranca                         manda Hello a 224.0.0.5 con su Router ID
    Cada Hello interval             repite el Hello (por defecto 10 s)
    Recibe un Hello                 comprueba que TODO coincide; si sí, añade
                                    al vecino y pasa a Init / 2-Way
    Pasa el Dead interval sin       da al vecino por caído, borra sus LSA y
    recibir Hello (4x hello)        vuelve a ejecutar Dijkstra
    Cambia un enlace suyo           inunda una LSU con la LSA actualizada
    Recibe una LSA nueva            la guarda, la CONFIRMA con LSAck, la
                                    reenvía a los demás vecinos y recalcula
    Recibe una LSA que ya tiene     la descarta (compara nº de secuencia)
    Cada 30 minutos                 refresca sus propias LSA aunque nada haya
                                    cambiado

  TIPOS DE LSA
    1  Router-LSA    los enlaces del propio router. No sale de su área
    2  Network-LSA   la genera el DR para describir una red multiacceso
    3  Summary-LSA   una red de otra área, la genera el ABR
    4  Summary ASBR  cómo llegar al ASBR
    5  AS-external   rutas de fuera de OSPF, las genera el ASBR
    7  NSSA-external como la 5 pero dentro de un área NSSA

  CÓMO SE VE EN EL VOLCADO
    IP protocolo 89 (0x59), destino 224.0.0.5, TTL 1, TOS 0xc0.
    Cabecera OSPF de 24 bytes: versión, tipo, longitud, Router ID, Area ID,
    checksum, tipo de autenticación y 8 bytes de autenticación.
    En un Hello, después: máscara, hello interval, opciones, prioridad,
    dead interval, DR, BDR y la lista de vecinos.

  RIP CONTRA OSPF, EN UNA TABLA
                          RIP                     OSPF
    Familia               vector distancia        estado de enlace
    Qué conoce            solo la dirección y     el mapa completo del área
                          la distancia
    Algoritmo             Bellman-Ford            Dijkstra
    Métrica               saltos (máx 15)         coste por ancho de banda
    Qué manda             su tabla entera         los cambios (LSA)
    Cada cuánto           cada 30 s siempre       solo cuando algo cambia
    Convergencia          lenta (minutos)         rápida (segundos)
    Escala                redes pequeñas          redes grandes, con áreas
    Transporte            UDP 520                 IP protocolo 89
    Autenticación         solo en v2              sí, texto o MD5
""".format(B=B)


TEORIA_GBN = """
GO-BACK-N  ·  TEORÍA Y REGLAS DE ACTUACIÓN
{B}
  LA IDEA
    Ventana deslizante con ACK ACUMULATIVO y un receptor tonto a propósito.
    El emisor puede tener hasta N paquetes en vuelo. El receptor solo acepta
    el que toca; cualquier cosa adelantada la tira. Si algo se pierde, el
    emisor RETROCEDE N y reenvía desde el paquete perdido en adelante.

    Simple de implementar, caro en ancho de banda.

  VARIABLES DEL EMISOR
    base          el paquete más antiguo enviado y todavía sin confirmar
    nextseqnum    el siguiente número que se usará al enviar
    N             tamaño de la ventana
    Un ÚNICO temporizador, asociado siempre al paquete «base»
    Ventana = [base, base+N-1].  Se puede enviar si nextseqnum < base+N

  EMISOR: QUÉ HACER ANTE CADA EVENTO
    Evento                       Acción
    ---------------------------  ---------------------------------------------
    La aplicación quiere         si nextseqnum < base + N:
    enviar datos                     enviar paquete(nextseqnum)
                                     si base == nextseqnum: arrancar timer
                                     nextseqnum = nextseqnum + 1
                                 si no: la ventana está llena -> rechazar el
                                     dato o hacer esperar a la aplicación
    Llega ACK(n) correcto        base = n + 1
                                 si base == nextseqnum: parar el timer
                                     (ya no queda nada sin confirmar)
                                 si no: REINICIAR el timer
    Vence el temporizador        reiniciar el timer
                                 reenviar TODOS los paquetes desde base hasta
                                 nextseqnum-1, en orden
    Llega un ACK corrupto        no hacer nada (el timer acabará saltando)

  RECEPTOR: QUÉ HACER ANTE CADA EVENTO
    Variable única: expectedseqnum (lo siguiente que espera). NO hay buffer.

    Evento                       Acción
    ---------------------------  ---------------------------------------------
    Llega el paquete esperado    entregar los datos a la aplicación
    y sin errores                enviar ACK(expectedseqnum)
                                 expectedseqnum = expectedseqnum + 1
    Cualquier otro caso          DESCARTAR el paquete
    (fuera de orden, corrupto)   reenviar ACK(expectedseqnum - 1), o sea
                                 repetir el último ACK correcto

  CONSECUENCIAS QUE HAY QUE SABER EXPLICAR
    · Un ACK acumulativo n confirma TODO lo anterior a n. Por eso perder un
      ACK no es grave: el siguiente que llegue lo cubre.
    · Si se pierde el paquete k y la ventana tenía N paquetes en vuelo, se
      retransmiten los que van de k hasta el último enviado. Los posteriores
      se reenvían aunque hubieran llegado bien, porque el receptor los tiró.
    · Con muchas pérdidas y ventana grande, la eficiencia se hunde.
    · El receptor no necesita memoria: esa es toda su ventaja.

  RESTRICCIÓN DEL TAMAÑO DE VENTANA
    Con k bits de número de secuencia (2^k valores):     N <= 2^k - 1
    Se resta uno porque, si la ventana ocupara todo el espacio, un ACK perdido
    haría imposible distinguir «ventana nueva completa» de «retransmisión
    completa de la anterior».
""".format(B=B)


TEORIA_SR = """
SELECTIVE REPEAT  ·  TEORÍA Y REGLAS DE ACTUACIÓN
{B}
  LA IDEA
    Ventana deslizante con ACK INDIVIDUAL y un receptor con memoria. Cada
    paquete lleva su propio temporizador y se confirma por separado. Si algo
    se pierde, se retransmite SOLO eso; lo demás ya está guardado en el buffer
    del receptor esperando a que llegue el hueco.

    Eficiente en ancho de banda, caro en complejidad y memoria.

  VARIABLES DEL EMISOR
    base            el más antiguo sin confirmar
    nextseqnum      el siguiente a enviar
    N               tamaño de la ventana
    UN TEMPORIZADOR POR CADA paquete enviado y no confirmado
    Una marca de «confirmado / sin confirmar» por cada paquete de la ventana

  EMISOR: QUÉ HACER ANTE CADA EVENTO
    Evento                       Acción
    ---------------------------  ---------------------------------------------
    La aplicación quiere         si nextseqnum está en [base, base+N-1]:
    enviar datos                     enviar paquete(nextseqnum)
                                     arrancar el timer DE ESE paquete
                                     nextseqnum = nextseqnum + 1
                                 si no: esperar
    Vence el timer del           reenviar SOLO el paquete n
    paquete n                    reiniciar SOLO su timer
    Llega ACK(n) con n dentro    marcar n como confirmado
    de la ventana                parar su timer
                                 si n == base:
                                     avanzar base hasta el primer paquete aún
                                     sin confirmar
                                     enviar los paquetes que con ese avance
                                     hayan entrado en la ventana
                                 si n != base: NO se mueve la ventana
                                     (el hueco sigue ahí, esperando)

  RECEPTOR: QUÉ HACER ANTE CADA EVENTO
    El receptor tiene su PROPIA ventana [rcv_base, rcv_base+N-1] y un buffer.

    Evento                       Acción
    ---------------------------  ---------------------------------------------
    Llega el paquete n y está    enviar ACK(n)   -- siempre, aunque llegue
    en [rcv_base, rcv_base+N-1]                     desordenado
                                 si n == rcv_base:
                                     entregar a la aplicación n y todos los
                                     contiguos que ya estén en el buffer
                                     avanzar rcv_base hasta el primer hueco
                                 si n != rcv_base:
                                     GUARDARLO en el buffer, sin entregarlo
    Llega el paquete n y está    enviar ACK(n) de todas formas
    en [rcv_base-N, rcv_base-1]  (ya lo tenía, pero su ACK debió perderse; si
                                 no se lo reconfirmo, el emisor se atasca)
    Cualquier otro caso          ignorarlo

  EL DETALLE QUE SIEMPRE CAE EN EL EXAMEN
    Emisor y receptor tienen ventanas DISTINTAS y desincronizadas. El receptor
    puede haber avanzado ya mientras el emisor sigue esperando un ACK perdido.
    Por eso la regla de reconfirmar los paquetes anteriores a rcv_base no es
    un detalle menor: sin ella la conexión se bloquea.

  RESTRICCIÓN DEL TAMAÑO DE VENTANA
    Con k bits de número de secuencia:     N <= 2^k / 2  =  2^(k-1)

    Por qué la mitad y no 2^k - 1 como en GBN: como el receptor de SR ACEPTA
    paquetes fuera de orden, si las ventanas del emisor y del receptor pudieran
    solaparse tras un ciclo de numeración, un duplicado retransmitido se
    colaría como si fuera un dato nuevo, y el flujo se corrompería sin que
    nadie lo detecte.

  CONSECUENCIAS QUE HAY QUE SABER EXPLICAR
    · Una pérdida de DATOS cuesta 1 retransmisión (en GBN cuesta muchas).
    · Una pérdida de ACK sí cuesta una retransmisión inútil, porque no hay
      ningún ACK posterior que la cubra. En GBN el ACK acumulativo la repara
      sola: por eso ante pérdida de ACK, GBN puede salir GANANDO.
    · Hace falta buffer y un timer por paquete en los dos extremos.
""".format(B=B)


FORMULARIO = """
FORMULARIO  ·  VENTANA DESLIZANTE, GBN Y SR
{B}
  TAMAÑO MÁXIMO DE VENTANA  (con k bits de número de secuencia)
    Stop-and-wait      N = 1
    Go-Back-N          N <= 2^k - 1
    Selective Repeat   N <= 2^(k-1)

    k=3 (8 números)  ->  GBN 7    SR 4
    k=4 (16)         ->  GBN 15   SR 8
    k=5 (32)         ->  GBN 31   SR 16

  RETRANSMISIONES ANTE UNA PÉRDIDA
    Se pierde el paquete p y el último enviado fue u
    Go-Back-N          u - p + 1     (el perdido y todos los de después)
    Selective Repeat   1             (solo el perdido)

  TIEMPOS Y RENDIMIENTO
    Tiempo de transmisión      T = L / R      (L bits del paquete, R bps)
    RTT                        ida y vuelta, sin contar T
    Utilización stop-and-wait  U = T / (RTT + T)
    Utilización con ventana N  U = N·T / (RTT + T),  con tope en 1
    Ventana que satura         N >= (RTT + T) / T
    Producto ancho banda-retardo (bytes)
                               BDP = R · RTT / 8
    Eficiencia observada       paquetes útiles / paquetes transmitidos

  TCP EN CONCRETO
    Bytes que pueden estar en vuelo    min(cwnd, rwnd)
    Ventana real anunciada             campo window · 2^s   (s = window scale)
    Máximo del campo window            65535 (16 bits) sin escala
    ACK que devuelve el receptor       seq + len del último segmento en orden
    seq del siguiente segmento         seq + len  (no depende de los ACK)
    SYN y FIN                          consumen 1 número de secuencia cada uno
    Retransmisión rápida                a los 3 ACK duplicados

  CÓMO ELEGIR QUÉ APLICAR
    Situación                                  Qué conviene
    -----------------------------------------  ---------------------------
    Enlace con muchas pérdidas de datos        Selective Repeat
    Enlace donde se pierden ACK                Go-Back-N aguanta mejor
    Receptor con poca memoria                  Go-Back-N
    Enlace rápido con RTT alto                 ventana grande + escalado
    Enlace lento y corto                       casi da igual: N pequeña basta

  ERRORES TÍPICOS QUE HAY QUE EVITAR
    · Confundir el ACK acumulativo (GBN, TCP) con el individual (SR).
    · Olvidar que el SYN y el FIN gastan un número de secuencia.
    · Aplicar el window scaling al propio paquete SYN: NO se aplica ahí.
    · Creer que el seq del emisor se frena cuando se pierde algo: no se frena,
      lo que se queda atascado es el ACK del receptor.
    · Usar N <= 2^k - 1 en Selective Repeat: ahí la cota es la mitad.
""".format(B=B)


TEORIA_TCP_REAL = """
QUÉ HACE TCP EN REALIDAD  ·  EL HÍBRIDO DE GBN Y SR
{B}
  TCP no es Go-Back-N ni Selective Repeat: toma de cada uno lo que le conviene.
  Esta es la tabla que hay que saber responder.

    Mecanismo                        ¿De dónde viene?
    -------------------------------  -----------------------------------------
    ACK acumulativo                  de GBN
    Un solo temporizador, para el    de GBN
    segmento más antiguo sin
    confirmar
    El receptor SÍ guarda en buffer  de SR  (GBN lo tiraría)
    lo que llega fuera de orden
    Al vencer el timer retransmite   de SR  (GBN reenviaría toda la ventana)
    UN SOLO segmento
    La opción SACK confirma bloques  de SR
    sueltos
    Numera BYTES, no paquetes        de ninguno de los dos: es propio de TCP

    En una frase: TCP CONFIRMA como Go-Back-N y RETRANSMITE como Selective
    Repeat.

  LO QUE TCP HACE Y NINGUNO DE LOS DOS MODELOS CONTEMPLA
    · Numeración por bytes, no por paquetes. El seq es el número del primer
      byte de datos del segmento, no un contador de segmentos.
    · SYN y FIN consumen un número de secuencia aunque no lleven datos.
    · Control de FLUJO con la ventana anunciada (rwnd) y control de
      CONGESTIÓN con una ventana interna (cwnd). GBN y SR solo modelan el
      primero, y con N fija.
    · La ventana NO es fija: cwnd crece y se hunde según cómo vaya la red.
    · Retransmisión rápida a los 3 ACK duplicados, sin esperar al timer.
    · El temporizador no es un valor fijo: se calcula midiendo el RTT.

  QUÉ HACE EL EMISOR ANTE CADA EVENTO
    Evento                       Acción
    ---------------------------  ---------------------------------------------
    Datos de la aplicación       si hay hueco en min(cwnd, rwnd):
                                     enviar segmento con seq = siguiente byte
                                     si no hay timer corriendo, arrancarlo
    Vence el temporizador        retransmitir SOLO el segmento más antiguo
                                 sin confirmar
                                 DUPLICAR el RTO (backoff exponencial)
                                 cwnd = 1 MSS  y  ssthresh = cwnd/2
                                 volver a arranque lento
    Llega ACK(n) nuevo           base = n; deslizar la ventana
    (n > base)                   si queda algo sin confirmar, reiniciar timer
                                 aumentar cwnd según la fase
    Llega el 3er ACK duplicado   RETRANSMISIÓN RÁPIDA: reenviar ese segmento
                                 sin esperar al timer
                                 ssthresh = cwnd/2,  cwnd = ssthresh + 3 MSS
                                 (recuperación rápida)
    El receptor anuncia win=0    dejar de enviar y mandar window probes
                                 periódicos hasta que anuncie espacio

  QUÉ HACE EL RECEPTOR ANTE CADA EVENTO
    Evento                       Acción
    ---------------------------  ---------------------------------------------
    Llega el segmento esperado   entregar a la aplicación, junto con los
    y no hay huecos pendientes   contiguos que tuviera en buffer
                                 ACK retardado: esperar hasta 500 ms por si
                                 llega otro segmento y confirmar los dos juntos
    Llega el esperado y había    entregar todo lo contiguo que ya se pueda
    un hueco que este rellena    mandar el ACK INMEDIATAMENTE
    Llega un segmento fuera      GUARDARLO en el buffer (esto es de SR)
    de orden                     mandar de inmediato un ACK DUPLICADO, con el
                                 número del byte que sigue faltando
                                 si hay SACK, indicar qué bloques ya tiene
    Llega un segmento repetido   descartar los datos y volver a confirmar

  CÁLCULO DEL TEMPORIZADOR  (RFC 6298)
    Se mide el RTT de los segmentos y se suaviza:
        SRTT    = (1 - a)·SRTT    + a·RTT_medido        con a = 1/8
        RTTVAR  = (1 - b)·RTTVAR  + b·|SRTT - RTT|      con b = 1/4
        RTO     = SRTT + 4·RTTVAR      (mínimo 1 segundo)
    Regla de Karn: NO se mide el RTT de un segmento retransmitido, porque no
    se sabría a cuál de los dos envíos corresponde el ACK.
    Al vencer el RTO se DUPLICA (backoff), hasta que llegue un ACK limpio.

  CONTROL DE CONGESTIÓN: LAS TRES FASES
    Arranque lento          cwnd empieza en 1 MSS y se DUPLICA cada RTT
    (slow start)            (crecimiento exponencial). Termina al llegar a
                            ssthresh o al detectar una pérdida.
    Evitación de            cwnd crece 1 MSS por RTT (crecimiento lineal).
    congestión              Es el «tanteo» prudente del límite de la red.
    Recuperación rápida     tras 3 ACK duplicados: no se vuelve a 1, se baja
                            a la mitad y se sigue desde ahí.

    Por qué la diferencia entre timeout y 3 ACK duplicados:
      · 3 ACK duplicados = los segmentos posteriores SÍ están llegando, la red
        funciona y solo se perdió uno -> se reacciona suave.
      · Timeout = no llega nada de nada, la red puede estar colapsada
        -> se reacciona drástico, cwnd = 1.

  DÓNDE SE VE CADA COSA EN EL VOLCADO
    rwnd                campo window (2 bytes, offset 0x30 en Ethernet+IPv4)
    escala de rwnd      opción kind 3, solo en el handshake
    SACK permitido      opción kind 4 en el SYN;  bloques con kind 5
    MSS                 opción kind 2, solo en el SYN
    Timestamps          opción kind 8: sirven para medir el RTT con precisión
    ACK duplicados      varios ACK seguidos con el MISMO número
    cwnd                NO SE VE. Es una variable interna del emisor y jamás
                        viaja por la red.

  RESUMEN DE LOS TRES, UNO AL LADO DEL OTRO
                        Go-Back-N        Selective Repeat   TCP
    ACK                 acumulativo      individual         acumulativo (+SACK)
    Fuera de orden      se descarta      se guarda          se guarda
    Timers              uno              uno por paquete    uno (+ fast retr.)
    Al perderse uno     reenvía todos    reenvía ese        reenvía ese
    Ventana             fija (N)         fija (N)           variable
    Unidad              paquetes         paquetes           bytes
    Congestión          no la modela     no la modela       sí, cwnd
""".format(B=B)


CAB_RIP = """
CABECERA RIPv2  ·  sobre UDP 520, empieza en 0x002a
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    Comando    |    Versión    |            en cero            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             AFI               |          Route tag            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      Red anunciada                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Máscara                                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Next hop                                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Métrica                                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   (el bloque de 20 bytes, de AFI a Métrica, se repite por cada ruta)

  rel  campo
  +0   Comando      1 = Request (pide la tabla)  ·  2 = Response (la anuncia)
  +1   Versión      2
  +4   AFI          2 = IPv4.  AFI 0 con métrica 16 = «mándame la tabla entera»
  +6   Route tag    marca rutas redistribuidas de otro protocolo
  +8   Red          la red que el router dice alcanzar
  +12  Máscara      solo existe en v2; es lo que permite VLSM y CIDR
  +16  Next hop     0.0.0.0 = «mándamelo a mí»
  +20  Métrica      saltos. 1 = directamente conectada. 16 = inalcanzable

  Número de rutas = (longitud UDP - 8 - 4) / 20
  Un paquete RIP no puede llevar más de 25 rutas (límite del datagrama).
""".format(B=B)


CAB_OSPF = """
CABECERA OSPFv2  ·  sobre IP protocolo 89, empieza en 0x0022
{B}
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    Versión    |      Tipo     |           Longitud            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Router ID                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Area ID                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Checksum             |          AuType               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   Autenticación (8 bytes)                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   (24 bytes de cabecera; después viene el cuerpo según el tipo)

  rel  abs     campo
  +0   0x0022  Versión     2 para IPv4
  +1   0x0023  Tipo        1 Hello · 2 DBD · 3 LSR · 4 LSU · 5 LSAck
  +2   0x0024  Longitud    bytes del paquete OSPF, cabecera incluida
  +4   0x0026  Router ID   identificador de 32 bits; NO es una dirección
  +8   0x002a  Area ID     0.0.0.0 es el backbone
  +12  0x002e  Checksum
  +14  0x0030  AuType      0 ninguna · 1 texto en claro · 2 MD5

  CUERPO DE UN HELLO  (a partir de 0x003a)
  +24  0x003a  Máscara de red          debe coincidir con la del vecino
  +28  0x003e  Hello interval          por defecto 10 s. Debe coincidir
  +30  0x0040  Opciones                bit E = acepta rutas externas
  +31  0x0041  Prioridad               para elegir DR. 0 = no quiero serlo
  +32  0x0042  Dead interval           por defecto 40 s (4x hello). Coincidir
  +36  0x0046  Designated Router       0.0.0.0 = aún no elegido
  +40  0x004a  Backup DR
  +44  0x004e  Lista de vecinos        4 bytes por Router ID oído

  CUERPO DE UN LSU
  +24  número de LSA que vienen, y a continuación las LSA una tras otra.
       Cada LSA empieza por: edad(2) · opciones(1) · TIPO(1) · Link State ID(4)
       · router anunciante(4) · nº de secuencia(4) · checksum(2) · longitud(2)
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
    ("cabrip",    "Cabecera RIPv2",                   CAB_RIP),
    ("cabospf",   "Cabecera OSPFv2 y cuerpo del Hello", CAB_OSPF),
    ("tablas",    "Tablas de valores y ASCII",        TABLAS),
    ("ventana",   "Ventana deslizante: resumen",      VENTANA),
    ("teoriarip", "TEORÍA de RIP y qué hace el router", TEORIA_RIP),
    ("teoriaospf","TEORÍA de OSPF y qué hace el router", TEORIA_OSPF),
    ("gbn",       "TEORÍA de Go-Back-N, regla a regla", TEORIA_GBN),
    ("sr",        "TEORÍA de Selective Repeat, regla a regla", TEORIA_SR),
    ("tcpreal",   "QUÉ HACE TCP: el híbrido de GBN y SR", TEORIA_TCP_REAL),
    ("formulario","FORMULARIO: fórmulas y qué aplicar", FORMULARIO),
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
