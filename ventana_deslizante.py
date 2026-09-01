#!/usr/bin/env python3
"""
VISUAL SLIDING WINDOW SIMULATOR
===============================
Draws in the terminal exactly what happens in Go-Back-N and in Selective
Repeat when something is lost, with time diagrams (sender/receiver ladder)
and the window evolving step by step.

Everything can be changed: window size, number of packets, propagation delay,
timeout, which data packet is lost and which ACK is lost.

Usage:
    python3 ventana_deslizante.py                interactive menu
    python3 ventana_deslizante.py --random       random scenario
    python3 ventana_deslizante.py --compare      GBN and SR, same loss
    python3 ventana_deslizante.py --examples     several ready-made scenarios

From the game: the "Go-Back-N and Selective Repeat simulator" menu option.
"""

import random
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

A = "=" * 74
B = "-" * 74
LIMITE_T = 400          # time cap so it can never hang


# ---------------------------------------------------------------------------
# Simulation model
# ---------------------------------------------------------------------------

@dataclass
class Evento:
    t: int
    lado: str        # "sender" | "receiver"
    texto: str


@dataclass
class Foto:
    """State of the sender window at one instant."""
    t: int
    base: int
    transmitidos: Set[int]
    confirmados: Set[int]
    nota: str = ""


@dataclass
class Resultado:
    protocolo: str
    total: int
    N: int
    retardo: int
    timeout: int
    perder_datos: Set[int]
    perder_ack: Set[int]
    eventos: List[Evento] = field(default_factory=list)
    fotos: List[Foto] = field(default_factory=list)
    transmisiones: int = 0
    retransmisiones: int = 0
    acks_enviados: int = 0
    entregados: List[int] = field(default_factory=list)
    t_final: int = 0
    completado: bool = True


def _min_bits(N: int, protocolo: str) -> int:
    """Minimum sequence-number bits needed for that window size."""
    k = 1
    while k < 16:
        cabe = (2 ** k - 1) if protocolo == "GBN" else (2 ** (k - 1))
        if cabe >= N:
            return k
        k += 1
    return k


# ---------------------------------------------------------------------------
# Go-Back-N
# ---------------------------------------------------------------------------

def simular_gbn(total: int, N: int, retardo: int, timeout: int,
                perder_datos: Set[int], perder_ack: Set[int]) -> Resultado:
    r = Resultado("GBN", total, N, retardo, timeout,
                  set(perder_datos), set(perder_ack))

    base = 0                 # oldest unacknowledged packet
    siguiente = 0            # next sequence number not yet sent
    esperado = 0             # what the receiver is expecting
    cola: List[int] = []     # packets waiting their turn to be sent
    datos_vuelo: List[Tuple[int, int]] = []   # (arrival_time, seq)
    acks_vuelo: List[Tuple[int, int]] = []    # (arrival_time, cumulative ack)
    intentos: Dict[int, int] = defaultdict(int)
    intentos_ack: Dict[int, int] = defaultdict(int)
    t_temporizador: Optional[int] = None      # when the timer for base expires
    ocupado_hasta = -1

    transmitidos: Set[int] = set()

    def foto(t, nota=""):
        r.fotos.append(Foto(t, base, set(transmitidos), set(range(base)), nota))

    foto(0, "start")
    t = 0
    while base < total and t < LIMITE_T:
        # --- timeout: resend the WHOLE outstanding window ---
        if t_temporizador is not None and t >= t_temporizador and base < total:
            pendientes = list(range(base, siguiente))
            if len(pendientes) > 4:
                lista = f"{pendientes[0]}..{pendientes[-1]} ({len(pendientes)})"
            else:
                lista = ", ".join(str(x) for x in pendientes)
            r.eventos.append(Evento(t, "emisor",
                                    f"TIMEOUT {base} -> resends {lista}"))
            cola = pendientes
            t_temporizador = None

        # --- feed the queue while the window allows it ---
        while siguiente < total and siguiente < base + N and siguiente not in cola:
            if all(siguiente != x for x in cola):
                cola.append(siguiente)
                siguiente += 1

        # --- transmit one packet (takes one time unit on the channel) ---
        if cola and t > ocupado_hasta:
            seq = cola.pop(0)
            intentos[seq] += 1
            r.transmisiones += 1
            if intentos[seq] > 1:
                r.retransmisiones += 1
            ocupado_hasta = t
            transmitidos.add(seq)
            se_pierde = (seq in perder_datos and intentos[seq] == 1)
            marca = "resend" if intentos[seq] > 1 else "send"
            foto(t)
            if se_pierde:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ══✗  LOST"))
            else:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ═══════════►"))
                datos_vuelo.append((t + retardo, seq))
            if t_temporizador is None:
                t_temporizador = t + timeout

        # --- arrivals at the receiver ---
        for llegada, seq in [x for x in datos_vuelo if x[0] == t]:
            datos_vuelo.remove((llegada, seq))
            if seq == esperado:
                esperado += 1
                r.entregados.append(seq)
                r.eventos.append(Evento(
                    t, "receptor", f"got {seq} · DELIVERS · ACK {seq}"))
            else:
                r.eventos.append(Evento(
                    t, "receptor",
                    f"got {seq} · DISCARDS · "
                    + (f"repeats ACK {esperado - 1}" if esperado > 0
                       else "no ACK yet")))
            if esperado > 0:
                ack = esperado - 1
                intentos_ack[ack] += 1
                r.acks_enviados += 1
                if ack in perder_ack and intentos_ack[ack] == 1:
                    r.eventos.append(Evento(t, "receptor",
                                            f"  ✗══  ACK {ack} IS LOST"))
                else:
                    acks_vuelo.append((t + retardo, ack))

        # --- ACK arrivals at the sender ---
        for llegada, ack in [x for x in acks_vuelo if x[0] == t]:
            acks_vuelo.remove((llegada, ack))
            if ack >= base:
                anterior = base
                base = ack + 1
                r.eventos.append(Evento(
                    t, "emisor",
                    f"◄═══════════  ACK {ack} · base={base}"))
                foto(t, f"ACK {ack}")
                t_temporizador = t + timeout if base < siguiente else None
                del anterior
            else:
                r.eventos.append(Evento(
                    t, "emisor",
                    f"◄═══════════  ACK {ack} duplicate"))

        t += 1

    r.t_final = t
    r.completado = base >= total
    foto(t, "end")
    return r


# ---------------------------------------------------------------------------
# Selective Repeat
# ---------------------------------------------------------------------------

def simular_sr(total: int, N: int, retardo: int, timeout: int,
               perder_datos: Set[int], perder_ack: Set[int]) -> Resultado:
    r = Resultado("SR", total, N, retardo, timeout,
                  set(perder_datos), set(perder_ack))

    base = 0
    siguiente = 0
    confirmados: Set[int] = set()
    rbase = 0                       # base of the receiver window
    buffer: Set[int] = set()        # received out of order
    cola: List[int] = []
    datos_vuelo: List[Tuple[int, int]] = []
    acks_vuelo: List[Tuple[int, int]] = []
    intentos: Dict[int, int] = defaultdict(int)
    intentos_ack: Dict[int, int] = defaultdict(int)
    temporizador: Dict[int, int] = {}     # seq -> expiry time
    ocupado_hasta = -1

    transmitidos: Set[int] = set()

    def foto(t, nota=""):
        r.fotos.append(Foto(t, base, set(transmitidos), set(confirmados), nota))

    foto(0, "start")
    t = 0
    while base < total and t < LIMITE_T:
        # --- per-packet timers ---
        for seq in sorted(temporizador):
            if temporizador[seq] <= t and seq not in confirmados:
                r.eventos.append(Evento(
                    t, "emisor", f"TIMEOUT {seq} -> resends ONLY {seq}"))
                if seq not in cola:
                    cola.append(seq)
                del temporizador[seq]
                break

        while siguiente < total and siguiente < base + N and siguiente not in cola:
            cola.append(siguiente)
            siguiente += 1

        if cola and t > ocupado_hasta:
            seq = cola.pop(0)
            intentos[seq] += 1
            r.transmisiones += 1
            if intentos[seq] > 1:
                r.retransmisiones += 1
            ocupado_hasta = t
            transmitidos.add(seq)
            se_pierde = (seq in perder_datos and intentos[seq] == 1)
            marca = "resend" if intentos[seq] > 1 else "send"
            foto(t)
            if se_pierde:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ══✗  LOST"))
            else:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ═══════════►"))
                datos_vuelo.append((t + retardo, seq))
            temporizador[seq] = t + timeout

        for llegada, seq in [x for x in datos_vuelo if x[0] == t]:
            datos_vuelo.remove((llegada, seq))
            if seq < rbase:
                r.eventos.append(Evento(
                    t, "receptor", f"got {seq} · duplicate · ACK {seq}"))
            elif seq < rbase + N:
                buffer.add(seq)
                if seq == rbase:
                    entregar = []
                    while rbase in buffer:
                        buffer.discard(rbase)
                        entregar.append(rbase)
                        r.entregados.append(rbase)
                        rbase += 1
                    if len(entregar) > 3:
                        lista = f"{entregar[0]}..{entregar[-1]}"
                    else:
                        lista = ",".join(str(x) for x in entregar)
                    r.eventos.append(Evento(
                        t, "receptor",
                        f"got {seq} · DELIVERS {lista} · ACK {seq}"))
                else:
                    r.eventos.append(Evento(
                        t, "receptor",
                        f"got {seq} · BUFFERED · ACK {seq}"))
            else:
                r.eventos.append(Evento(t, "receptor",
                                        f"got {seq} · outside the window"))
                continue

            intentos_ack[seq] += 1
            r.acks_enviados += 1
            if seq in perder_ack and intentos_ack[seq] == 1:
                r.eventos.append(Evento(t, "receptor",
                                        f"  ✗══  ACK {seq} IS LOST"))
            else:
                acks_vuelo.append((t + retardo, seq))

        for llegada, ack in [x for x in acks_vuelo if x[0] == t]:
            acks_vuelo.remove((llegada, ack))
            if ack in confirmados:
                r.eventos.append(Evento(
                    t, "emisor", f"◄═══════════  ACK {ack} repeated"))
                continue
            confirmados.add(ack)
            temporizador.pop(ack, None)
            if ack == base:
                anterior = base
                while base in confirmados:
                    base += 1
                r.eventos.append(Evento(
                    t, "emisor",
                    f"◄═══════════  ACK {ack} · base {anterior}->{base}"))
                foto(t, f"ACK {ack} unblocks")
            else:
                r.eventos.append(Evento(
                    t, "emisor",
                    f"◄═══════════  ACK {ack} · {base} still missing"))
                foto(t, f"lone ACK {ack}")

        t += 1

    r.t_final = t
    r.completado = base >= total
    foto(t, "end")
    return r


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def barra_ventana(total: int, base: int, transmitidos: Set[int],
                  confirmados: Set[int], N: int) -> str:
    """One row with the state of every sequence number.

    ▓ acked   █ sent but unacked   ▒ inside the window, not sent yet
    ░ still outside the window
    """
    celdas = []
    for s in range(total):
        if s in confirmados or s < base:
            c = "▓"
        elif s in transmitidos:
            c = "█"
        elif s < base + N:
            c = "▒"
        else:
            c = "░"
        celdas.append(c)
    return "".join(celdas)


def regla_numeros(total: int) -> str:
    return "".join(str(s % 10) for s in range(total))


def dibujar_ventana(r: Resultado) -> str:
    lineas = ["", "  SENDER WINDOW OVER TIME", B,
              "    ▓ acknowledged    █ sent, not yet acknowledged",
              "    ▒ fits in the window, not sent yet    ░ outside the window",
              "",
              f"      packet   {regla_numeros(r.total)}"]

    vistas = []
    for f in r.fotos:
        barra = barra_ventana(r.total, f.base, f.transmitidos, f.confirmados, r.N)
        clave = (barra, f.base)
        if vistas and vistas[-1][0] == clave:
            continue
        vistas.append((clave, f, barra))

    for _, f, barra in vistas:
        tope = min(f.base + r.N - 1, r.total - 1)
        detalle = f"base={f.base}" + (f"  window=[{f.base}..{tope}]"
                                      if f.base < r.total else "  done")
        nota = f"  {f.nota}" if f.nota else ""
        lineas.append(f"      t={f.t:<6} {barra}   {detalle}{nota}")
    return "\n".join(lineas)


ANCHO_COL = 34


def _ajustar(texto: str, ancho: int = ANCHO_COL) -> str:
    """Truncate if needed, so the ladder never goes out of alignment."""
    if len(texto) <= ancho:
        return texto.ljust(ancho)
    return texto[:ancho - 1] + "…"


def dibujar_escalera(r: Resultado) -> str:
    sep = "  " + "─" * 5 + "┼" + "─" * (ANCHO_COL + 2) + "┼" + "─" * (ANCHO_COL - 2)
    lineas = ["", "  TIME DIAGRAM", B,
              f"  {'t':>4} │ {_ajustar('SENDER')} │ RECEIVER",
              sep]
    ultimo_t = None
    for e in r.eventos:
        marca = f"{e.t:>4}" if e.t != ultimo_t else "    "
        ultimo_t = e.t
        if e.lado == "emisor":
            lineas.append(f"  {marca} │ {_ajustar(e.texto)} │")
        else:
            lineas.append(f"  {marca} │ {_ajustar('')} │ "
                          f"{_ajustar(e.texto, ANCHO_COL).rstrip()}")
    return "\n".join(lineas)


def dibujar_resumen(r: Resultado) -> str:
    utiles = r.total
    desperdicio = r.transmisiones - utiles
    efic = 100 * utiles / r.transmisiones if r.transmisiones else 0
    k = _min_bits(r.N, r.protocolo)
    cabe = (2 ** k - 1) if r.protocolo == "GBN" else 2 ** (k - 1)
    return "\n".join([
        "", "  RESULT", B,
        f"    data transmissions ........... {r.transmisiones}",
        f"    of those, retransmissions .... {r.retransmisiones}",
        f"    useful packets ............... {utiles}",
        f"    wasted transmissions ......... {desperdicio}",
        f"    efficiency ................... {efic:.0f}%  "
        f"({utiles} useful out of {r.transmisiones} sent)",
        f"    ACKs sent .................... {r.acks_enviados}",
        f"    time to finish ............... {r.t_final} units",
        f"    delivered in order ........... "
        + ", ".join(str(x) for x in r.entregados),
        "",
        f"    With window N={r.N} this protocol needs at least k={k} sequence",
        f"    number bits (with {k} bits, {r.protocolo} allows up to {cabe}).",
    ])


def encabezado(r: Resultado) -> str:
    perdidas = []
    if r.perder_datos:
        perdidas.append("packet(s) " + ", ".join(str(x) for x in sorted(r.perder_datos)))
    if r.perder_ack:
        perdidas.append("ACK " + ", ".join(str(x) for x in sorted(r.perder_ack)))
    texto = " and ".join(perdidas) if perdidas else "nothing (perfect channel)"
    nombre = ("GO-BACK-N" if r.protocolo == "GBN" else "SELECTIVE REPEAT")
    return "\n".join([
        "", A,
        f"  {nombre}",
        f"  window N={r.N}   ·   {r.total} packets   ·   "
        f"delay={r.retardo}   ·   timeout={r.timeout}",
        f"  lost: {texto}",
        A])


def mostrar(r: Resultado, con_ventana: bool = True) -> None:
    print(encabezado(r))
    print(dibujar_escalera(r))
    if con_ventana:
        print(dibujar_ventana(r))
    print(dibujar_resumen(r))
    if not r.completado:
        print("\n  (the simulation was cut off by the time limit)")


# ---------------------------------------------------------------------------
# Comparing the two protocols on the same scenario
# ---------------------------------------------------------------------------

def comparar(total: int, N: int, retardo: int, timeout: int,
             perder_datos: Set[int], perder_ack: Set[int],
             con_diagramas: bool = True) -> None:
    gbn = simular_gbn(total, N, retardo, timeout, perder_datos, perder_ack)
    sr = simular_sr(total, N, retardo, timeout, perder_datos, perder_ack)

    if con_diagramas:
        mostrar(gbn)
        mostrar(sr)

    print("\n" + A)
    print("  SAME LOSS, BOTH PROTOCOLS")
    print(A)
    filas = [
        ("data transmissions", gbn.transmisiones, sr.transmisiones),
        ("retransmissions", gbn.retransmisiones, sr.retransmisiones),
        ("ACKs sent", gbn.acks_enviados, sr.acks_enviados),
        ("total time", gbn.t_final, sr.t_final),
    ]
    print(f"    {'':<26} {'Go-Back-N':>12} {'Selective Repeat':>18}")
    print("    " + "-" * 58)
    for nombre, a, b in filas:
        print(f"    {nombre:<26} {a:>12} {b:>18}")
    ef_g = 100 * total / gbn.transmisiones if gbn.transmisiones else 0
    ef_s = 100 * total / sr.transmisiones if sr.transmisiones else 0
    print(f"    {'efficiency':<26} {ef_g:>11.0f}% {ef_s:>17.0f}%")

    ahorro = gbn.transmisiones - sr.transmisiones
    print()
    if ahorro > 0:
        print(f"    Selective Repeat sent {ahorro} packet(s) fewer. Go-Back-N also")
        print("    retransmitted the ones that had already arrived fine, because")
        print("    its receiver discards them instead of buffering them.")
    elif ahorro == 0:
        print("    A tie here: there were no packets after the lost one inside the")
        print("    window, so Go-Back-N never resent anything extra.")
    else:
        print(f"    GO-BACK-N wins here by {-ahorro} transmission(s), and that is not")
        print("    a bug: when an ACK is lost the advantage flips over.")
        print("    Go-Back-N ACKs are CUMULATIVE, so the next ACK that arrives")
        print("    already confirms whatever was left unconfirmed: the loss heals")
        print("    itself. In Selective Repeat each ACK confirms a single packet,")
        print("    so if that ACK is lost nothing covers it and the timer ends up")
        print("    retransmitting a packet that HAD already arrived fine.")
        print("    In short: SR wins when DATA is lost, GBN copes better when")
        print("    ACKs are lost.")
    print(f"\n    Minimum sequence bits:  GBN k={_min_bits(N, 'GBN')}   "
          f"SR k={_min_bits(N, 'SR')}   (for a window of {N})")


# ---------------------------------------------------------------------------
# Ready-made and random scenarios
# ---------------------------------------------------------------------------

ESCENARIOS = [
    ("Small window (N=2), a middle packet is lost",
     dict(total=6, N=2, retardo=3, timeout=9, perder_datos={2}, perder_ack=set())),
    ("Medium window (N=4), a middle packet is lost",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos={2}, perder_ack=set())),
    ("Large window (N=6): this is where Go-Back-N really suffers",
     dict(total=10, N=6, retardo=3, timeout=12, perder_datos={1}, perder_ack=set())),
    ("An ACK is lost, not a data packet",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos=set(), perder_ack={1})),
    ("The FIRST packet is lost: it blocks the whole window",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos={0}, perder_ack=set())),
    ("The LAST packet of the batch is lost",
     dict(total=6, N=4, retardo=3, timeout=10, perder_datos={5}, perder_ack=set())),
    ("Two losses: a packet and also an ACK",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos={2}, perder_ack={4})),
    ("ACK loss with a large window: Go-Back-N wins here",
     dict(total=10, N=6, retardo=3, timeout=10, perder_datos=set(), perder_ack={2})),
    ("Perfect channel, no losses (the baseline)",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos=set(), perder_ack=set())),
    ("Stop-and-wait: the sliding window with N=1",
     dict(total=5, N=1, retardo=3, timeout=9, perder_datos={2}, perder_ack=set())),
]


def escenario_azar() -> dict:
    N = random.choice([1, 2, 3, 4, 5, 6, 8])
    total = random.choice([6, 8, 10, 12])
    total = max(total, N + 2)
    retardo = random.choice([2, 3, 4])
    timeout = 2 * retardo + random.choice([2, 4, 6])
    modo = random.choice(["datos", "ack", "ambos", "nada"])
    perder_datos, perder_ack = set(), set()
    if modo in ("datos", "ambos"):
        perder_datos = {random.randrange(0, total)}
    if modo in ("ack", "ambos"):
        perder_ack = {random.randrange(0, max(1, total - 1))}
    return dict(total=total, N=N, retardo=retardo, timeout=timeout,
                perder_datos=perder_datos, perder_ack=perder_ack)


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

def menu(titulo: str, opciones: List[str]) -> int:
    print(f"\n{titulo}")
    for i, o in enumerate(opciones, 1):
        print(f"  {i}) {o}")
    while True:
        bruto = input("> ").strip()
        if bruto.isdigit() and 1 <= int(bruto) <= len(opciones):
            return int(bruto) - 1
        print(f"Type a number between 1 and {len(opciones)}.")


def pedir_entero(texto: str, por_defecto: int, minimo: int, maximo: int) -> int:
    bruto = input(f"{texto} (Enter = {por_defecto}): ").strip()
    if not bruto:
        return por_defecto
    try:
        return max(minimo, min(int(bruto), maximo))
    except ValueError:
        return por_defecto


def a_medida() -> dict:
    print("\nBuild your own scenario:")
    total = pedir_entero("  How many packets?", 8, 2, 20)
    N = pedir_entero("  Window size N", 4, 1, total)
    retardo = pedir_entero("  Propagation delay", 3, 1, 8)
    timeout = pedir_entero("  Timeout", 2 * retardo + 4, retardo + 1, 60)

    perder_datos, perder_ack = set(), set()
    idx = menu("  What gets lost?",
               ["A data packet", "An ACK", "Both", "Nothing"])
    if idx in (0, 2):
        d = pedir_entero(f"  Which packet is lost? (0 to {total - 1}, "
                         "-1 = random)", -1, -1, total - 1)
        perder_datos = {random.randrange(0, total) if d < 0 else d}
    if idx in (1, 2):
        a = pedir_entero(f"  Which ACK is lost? (0 to {total - 1}, "
                         "-1 = random)", -1, -1, total - 1)
        perder_ack = {random.randrange(0, total) if a < 0 else a}

    return dict(total=total, N=N, retardo=retardo, timeout=timeout,
                perder_datos=perder_datos, perder_ack=perder_ack)


def ejecutar(cfg: dict, cual: str = "ambos") -> None:
    if cual == "gbn":
        mostrar(simular_gbn(**cfg))
    elif cual == "sr":
        mostrar(simular_sr(**cfg))
    else:
        comparar(**cfg)


def interactivo() -> None:
    print(A)
    print("  SLIDING WINDOW SIMULATOR  ·  Go-Back-N and Selective Repeat")
    print(A)
    print("  Draws the sender/receiver time diagram and how the window slides,")
    print("  so you can see what each protocol resends when something is lost.")

    while True:
        idx = menu("What do you want to see?",
                   ["Compare both on a ready-made scenario",
                    "Random scenario",
                    "Custom scenario (I choose the parameters)",
                    "Go-Back-N only (ready-made scenario)",
                    "Selective Repeat only (ready-made scenario)",
                    "Walk through every ready-made scenario",
                    "Quit"])

        if idx == 6:
            return

        if idx == 1:
            ejecutar(escenario_azar())
            continue

        if idx == 2:
            ejecutar(a_medida())
            continue

        if idx == 5:
            for nombre, cfg in ESCENARIOS:
                print("\n\n" + "#" * 74)
                print(f"#  {nombre}")
                print("#" * 74)
                comparar(**cfg, con_diagramas=False)
                if input("\nEnter for the next one, \"q\" to stop: ").strip().lower() == "q":
                    break
            continue

        j = menu("Pick the scenario:", [n for n, _ in ESCENARIOS])
        cfg = ESCENARIOS[j][1]
        ejecutar(cfg, {0: "ambos", 3: "gbn", 4: "sr"}[idx])


def main() -> None:
    args = [a.lower() for a in sys.argv[1:]]
    if not args:
        interactivo()
        return
    if "--random" in args:
        ejecutar(escenario_azar())
    elif "--compare" in args:
        comparar(**ESCENARIOS[1][1])
    elif "--examples" in args:
        for nombre, cfg in ESCENARIOS:
            print("\n\n" + "#" * 74)
            print(f"#  {nombre}")
            print("#" * 74)
            comparar(**cfg, con_diagramas=False)
    elif "gbn" in args:
        mostrar(simular_gbn(**ESCENARIOS[1][1]))
    elif "sr" in args:
        mostrar(simular_sr(**ESCENARIOS[1][1]))
    else:
        print(__doc__)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n")
