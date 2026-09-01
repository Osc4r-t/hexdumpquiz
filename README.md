# hexdumpquiz

Juegos de consola para practicar análisis de tráfico de red leyendo el volcado
hexadecimal de paquetes reales.

## Archivos

| Archivo | Qué hace |
|---|---|
| `hex_dump_quiz.py` | **El principal.** Quiz sobre el hex dump de capturas reales. |
| `referencia.py` | Panel con el formato de todas las cabeceras y sus offsets. |
| `ventana_deslizante.py` | Simulador visual de Go-Back-N y Selective Repeat. |
| `pcap_quiz.py` | Versión anterior, basada en Scapy y en campos ya interpretados. |
| `files/` | Capturas `.pcap` y `.pcapng` con las que se juega. |

## Uso

```bash
python3 hex_dump_quiz.py
```

Elige una captura de `files/` y el menú ofrece:

1. **Jugar** — preguntas sobre el volcado.
2. **Modo estudio** — el hex dump con cada campo mapeado a sus offsets.
3. **Panel de cabeceras** — se abre en una ventana de terminal a la derecha (macOS).
4. **Simulador de ventana deslizante** — diagramas de Go-Back-N y Selective Repeat.

No hace falta instalar nada: `hex_dump_quiz.py`, `referencia.py` y
`ventana_deslizante.py` usan solo la librería estándar. Solo `pcap_quiz.py`
necesita Scapy (`python3 -m pip install scapy`).

## Qué se practica

**Lectura del volcado.** Cinco tipos de pregunta sobre los mismos bytes: el
valor de un campo, en qué offset empieza, qué campo son unos bytes resaltados,
cómo se decodifican, y qué bytes forman un campo.

**Cálculo.** IHL → longitud de cabecera, data offset → cabecera TCP, bytes de
datos, por qué el volcado mide 14 bytes más que la longitud IP, y verificación
real del checksum IPv4.

**Bits.** El byte `45` que contiene dos campos, y el byte de flags TCP
descompuesto máscara por máscara.

**Secuencias.** Grupos de 3 a 6 paquetes para deducir qué ocurre por su
contenido y su orden: handshake, cierre, escaneo de puertos, ping, flood, ARP
spoofing, resolución DNS, ciclo DORA de DHCP.

**Ventana deslizante.** Teoría y ejercicios de Go-Back-N y Selective Repeat,
más la ventana real anunciada en los paquetes TCP de la captura.

## Formatos soportados

Lector propio escrito con `struct`, sin dependencias:

- `.pcap` clásico (little y big endian, microsegundos y nanosegundos)
- `.pcapng`
- Capa de enlace: Ethernet, loopback BSD (NULL), Linux cooked (SLL), IP crudo

Protocolos que parsea byte a byte: Ethernet, ARP, IPv4, IPv6, ICMP, TCP (con
sus opciones), UDP, DNS, DHCP/BOOTP y HTTP.

## Simulador de ventana deslizante

```bash
python3 ventana_deslizante.py              # menú interactivo
python3 ventana_deslizante.py --comparar   # GBN y SR con la misma pérdida
python3 ventana_deslizante.py --ejemplos   # todos los escenarios preparados
python3 ventana_deslizante.py --azar       # escenario aleatorio
```

Dibuja el diagrama de tiempo emisor/receptor y la evolución de la ventana. Se
puede variar el tamaño de ventana, el número de paquetes, el retardo, el
temporizador y qué se pierde (un paquete de datos, un ACK, o los dos).

## Panel de referencia

```bash
python3 referencia.py          # panel completo
python3 referencia.py tcp      # una sección
python3 referencia.py --lista  # secciones disponibles
```

Doce secciones con diagramas estilo RFC, tabla de offsets de cada campo, y
tablas de valores (EtherTypes, protocolos IP, puertos, tipos ICMP y DNS, ASCII).
