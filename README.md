# hexdumpquiz

Juegos de consola para practicar análisis de tráfico de red leyendo el volcado
hexadecimal de paquetes reales.

## Archivos

| Archivo | Qué hace |
|---|---|
| `hex_dump_quiz.py` | **El principal.** Quiz sobre el hex dump de capturas reales. |
| `referencia.py` | Panel con el formato de todas las cabeceras y sus offsets. |
| `ventana_deslizante.py` | Simulador visual de Go-Back-N y Selective Repeat. |
| `tcp_escenarios.py` | Escenarios TCP aleatorios (SYN/ACK) en tres niveles. |
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
5. **Escenarios TCP aleatorios** — preguntas de SYN/ACK y ventana en tres niveles.

No hace falta instalar nada salvo para `pcap_quiz.py`: el resto usa solo la
librería estándar. Solo `pcap_quiz.py`
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

## Escenarios TCP aleatorios

```bash
python3 tcp_escenarios.py            # menú interactivo
python3 tcp_escenarios.py --dificil  # una ronda de ese nivel
python3 tcp_escenarios.py --demo     # un escenario con todas sus respuestas
```

Genera una situación distinta cada vez (handshake, envío de datos, una pérdida,
la ventana llenándose, cierre con FIN) y pregunta en tres niveles:

- **Fácil** — con el diagrama delante: flags, ISN, por qué el ACK del SYN es ISN+1.
- **Medio** — con el diagrama: calcular el siguiente seq/ack, ventana real con
  escala, segmentos que caben en la ventana, ACK duplicados.
- **Difícil** — **sin diagrama**, solo los parámetros escritos: hay que deducir
  los números de secuencia, en qué ACK se atasca el receptor tras una pérdida,
  cuántos segmentos caben antes de bloquearse por ventana llena, y qué seq
  consume el FIN.

El diagrama y las respuestas se derivan de la misma simulación, así que no
pueden contradecirse.
