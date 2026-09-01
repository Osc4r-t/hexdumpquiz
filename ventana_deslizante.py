#!/usr/bin/env python3
"""
SIMULADOR VISUAL DE VENTANA DESLIZANTE
======================================
Dibuja en la terminal qué pasa exactamente en Go-Back-N y en Selective Repeat
cuando se pierde algo, con diagramas de tiempo (escalera emisor/receptor) y la
evolución de la ventana paso a paso.

Se puede variar todo: tamaño de ventana, número de paquetes, retardo de
propagación, temporizador, qué paquete de datos se pierde y qué ACK se pierde.

Uso:
    python3 ventana_deslizante.py                menú interactivo
    python3 ventana_deslizante.py --azar         escenario aleatorio
    python3 ventana_deslizante.py --comparar     GBN y SR con la misma pérdida
    python3 ventana_deslizante.py --ejemplos     varios escenarios preparados

Desde el juego: opción «Simulador de ventana deslizante» del menú principal.
"""

import random
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

A = "=" * 74
B = "-" * 74
LIMITE_T = 400          # tope de tiempo para que nunca se cuelgue


# ---------------------------------------------------------------------------
# Modelo de la simulación
# ---------------------------------------------------------------------------

@dataclass
class Evento:
    t: int
    lado: str        # "emisor" | "receptor"
    texto: str


@dataclass
class Foto:
    """Estado de la ventana del emisor en un instante."""
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
    """Bits de número de secuencia mínimos para esa ventana."""
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

    base = 0                 # primer paquete no confirmado
    siguiente = 0            # siguiente número aún no enviado
    esperado = 0             # lo que espera el receptor
    cola: List[int] = []     # paquetes esperando su turno de transmisión
    datos_vuelo: List[Tuple[int, int]] = []   # (t_llegada, seq)
    acks_vuelo: List[Tuple[int, int]] = []    # (t_llegada, ack acumulativo)
    intentos: Dict[int, int] = defaultdict(int)
    intentos_ack: Dict[int, int] = defaultdict(int)
    t_temporizador: Optional[int] = None      # cuándo vence el timer del base
    ocupado_hasta = -1

    transmitidos: Set[int] = set()

    def foto(t, nota=""):
        r.fotos.append(Foto(t, base, set(transmitidos), set(range(base)), nota))

    foto(0, "arranque")
    t = 0
    while base < total and t < LIMITE_T:
        # --- vence el temporizador: se reenvía TODA la ventana pendiente ---
        if t_temporizador is not None and t >= t_temporizador and base < total:
            pendientes = list(range(base, siguiente))
            if len(pendientes) > 4:
                lista = f"{pendientes[0]}..{pendientes[-1]} ({len(pendientes)})"
            else:
                lista = ", ".join(str(x) for x in pendientes)
            r.eventos.append(Evento(t, "emisor",
                                    f"TIMEOUT {base} → reenvía {lista}"))
            cola = pendientes
            t_temporizador = None

        # --- alimentar la cola mientras la ventana lo permita ---
        while siguiente < total and siguiente < base + N and siguiente not in cola:
            if all(siguiente != x for x in cola):
                cola.append(siguiente)
                siguiente += 1

        # --- transmitir un paquete (ocupa una unidad de tiempo el canal) ---
        if cola and t > ocupado_hasta:
            seq = cola.pop(0)
            intentos[seq] += 1
            r.transmisiones += 1
            if intentos[seq] > 1:
                r.retransmisiones += 1
            ocupado_hasta = t
            transmitidos.add(seq)
            se_pierde = (seq in perder_datos and intentos[seq] == 1)
            marca = "reenv" if intentos[seq] > 1 else "envía"
            foto(t)
            if se_pierde:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ══✗  SE PIERDE"))
            else:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ═══════════►"))
                datos_vuelo.append((t + retardo, seq))
            if t_temporizador is None:
                t_temporizador = t + timeout

        # --- llegadas al receptor ---
        for llegada, seq in [x for x in datos_vuelo if x[0] == t]:
            datos_vuelo.remove((llegada, seq))
            if seq == esperado:
                esperado += 1
                r.entregados.append(seq)
                r.eventos.append(Evento(
                    t, "receptor", f"recibe {seq} · ENTREGA · ACK {seq}"))
            else:
                r.eventos.append(Evento(
                    t, "receptor",
                    f"recibe {seq} · DESCARTA · "
                    + (f"repite ACK {esperado - 1}" if esperado > 0
                       else "sin ACK aún")))
            if esperado > 0:
                ack = esperado - 1
                intentos_ack[ack] += 1
                r.acks_enviados += 1
                if ack in perder_ack and intentos_ack[ack] == 1:
                    r.eventos.append(Evento(t, "receptor",
                                            f"  ✗══  el ACK {ack} SE PIERDE"))
                else:
                    acks_vuelo.append((t + retardo, ack))

        # --- llegadas de ACK al emisor ---
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
                    f"◄═══════════  ACK {ack} duplicado"))

        t += 1

    r.t_final = t
    r.completado = base >= total
    foto(t, "fin")
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
    rbase = 0                       # base de la ventana del receptor
    buffer: Set[int] = set()        # recibidos fuera de orden
    cola: List[int] = []
    datos_vuelo: List[Tuple[int, int]] = []
    acks_vuelo: List[Tuple[int, int]] = []
    intentos: Dict[int, int] = defaultdict(int)
    intentos_ack: Dict[int, int] = defaultdict(int)
    temporizador: Dict[int, int] = {}     # seq -> instante de vencimiento
    ocupado_hasta = -1

    transmitidos: Set[int] = set()

    def foto(t, nota=""):
        r.fotos.append(Foto(t, base, set(transmitidos), set(confirmados), nota))

    foto(0, "arranque")
    t = 0
    while base < total and t < LIMITE_T:
        # --- temporizadores individuales ---
        for seq in sorted(temporizador):
            if temporizador[seq] <= t and seq not in confirmados:
                r.eventos.append(Evento(
                    t, "emisor", f"TIMEOUT {seq} → reenvía SOLO el {seq}"))
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
            marca = "reenv" if intentos[seq] > 1 else "envía"
            foto(t)
            if se_pierde:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ══✗  SE PIERDE"))
            else:
                r.eventos.append(Evento(t, "emisor",
                                        f"{marca} {seq}  ═══════════►"))
                datos_vuelo.append((t + retardo, seq))
            temporizador[seq] = t + timeout

        for llegada, seq in [x for x in datos_vuelo if x[0] == t]:
            datos_vuelo.remove((llegada, seq))
            if seq < rbase:
                r.eventos.append(Evento(
                    t, "receptor", f"recibe {seq} · repetido · ACK {seq}"))
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
                        f"recibe {seq} · ENTREGA {lista} · ACK {seq}"))
                else:
                    r.eventos.append(Evento(
                        t, "receptor",
                        f"recibe {seq} · al BUFFER · ACK {seq}"))
            else:
                r.eventos.append(Evento(t, "receptor",
                                        f"recibe {seq} · fuera de ventana"))
                continue

            intentos_ack[seq] += 1
            r.acks_enviados += 1
            if seq in perder_ack and intentos_ack[seq] == 1:
                r.eventos.append(Evento(t, "receptor",
                                        f"  ✗══  el ACK {seq} SE PIERDE"))
            else:
                acks_vuelo.append((t + retardo, seq))

        for llegada, ack in [x for x in acks_vuelo if x[0] == t]:
            acks_vuelo.remove((llegada, ack))
            if ack in confirmados:
                r.eventos.append(Evento(
                    t, "emisor", f"◄═══════════  ACK {ack} repetido"))
                continue
            confirmados.add(ack)
            temporizador.pop(ack, None)
            if ack == base:
                anterior = base
                while base in confirmados:
                    base += 1
                r.eventos.append(Evento(
                    t, "emisor",
                    f"◄═══════════  ACK {ack} · base {anterior}→{base}"))
                foto(t, f"ACK {ack} desbloquea")
            else:
                r.eventos.append(Evento(
                    t, "emisor",
                    f"◄═══════════  ACK {ack} · falta el {base}"))
                foto(t, f"ACK {ack} suelto")

        t += 1

    r.t_final = t
    r.completado = base >= total
    foto(t, "fin")
    return r


# ---------------------------------------------------------------------------
# Dibujo
# ---------------------------------------------------------------------------

def barra_ventana(total: int, base: int, transmitidos: Set[int],
                  confirmados: Set[int], N: int) -> str:
    """Una fila con el estado de cada número de secuencia.

    ▓ confirmado   █ enviado sin confirmar   ▒ dentro de ventana sin enviar
    ░ fuera de la ventana todavía
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
    lineas = ["", "  EVOLUCIÓN DE LA VENTANA DEL EMISOR", B,
              "    ▓ confirmado    █ enviado sin confirmar",
              "    ▒ cabe en la ventana, aún sin enviar    ░ fuera de la ventana",
              "",
              f"      paquete  {regla_numeros(r.total)}"]

    vistas = []
    for f in r.fotos:
        barra = barra_ventana(r.total, f.base, f.transmitidos, f.confirmados, r.N)
        clave = (barra, f.base)
        if vistas and vistas[-1][0] == clave:
            continue
        vistas.append((clave, f, barra))

    for _, f, barra in vistas:
        tope = min(f.base + r.N - 1, r.total - 1)
        detalle = f"base={f.base}" + (f"  ventana=[{f.base}..{tope}]"
                                      if f.base < r.total else "  completado")
        nota = f"  {f.nota}" if f.nota else ""
        lineas.append(f"      t={f.t:<6} {barra}   {detalle}{nota}")
    return "\n".join(lineas)


ANCHO_COL = 34


def _ajustar(texto: str, ancho: int = ANCHO_COL) -> str:
    """Recorta si hace falta, para que la escalera nunca se desalinee."""
    if len(texto) <= ancho:
        return texto.ljust(ancho)
    return texto[:ancho - 1] + "…"


def dibujar_escalera(r: Resultado) -> str:
    sep = "  " + "─" * 5 + "┼" + "─" * (ANCHO_COL + 2) + "┼" + "─" * (ANCHO_COL - 2)
    lineas = ["", "  DIAGRAMA DE TIEMPO", B,
              f"  {'t':>4} │ {_ajustar('EMISOR')} │ RECEPTOR",
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
        "", "  RESULTADO", B,
        f"    transmisiones de datos ....... {r.transmisiones}",
        f"    de ellas, retransmisiones .... {r.retransmisiones}",
        f"    paquetes útiles .............. {utiles}",
        f"    transmisiones desperdiciadas . {desperdicio}",
        f"    eficiencia ................... {efic:.0f}%  "
        f"({utiles} útiles de {r.transmisiones} enviadas)",
        f"    ACK enviados ................. {r.acks_enviados}",
        f"    tiempo hasta terminar ........ {r.t_final} unidades",
        f"    entregados en orden .......... "
        + ", ".join(str(x) for x in r.entregados),
        "",
        f"    Con ventana N={r.N}, este protocolo necesita al menos k={k} bits de",
        f"    número de secuencia (con {k} bits, {r.protocolo} admite hasta {cabe}).",
    ])


def encabezado(r: Resultado) -> str:
    perdidas = []
    if r.perder_datos:
        perdidas.append("paquete(s) " + ", ".join(str(x) for x in sorted(r.perder_datos)))
    if r.perder_ack:
        perdidas.append("ACK " + ", ".join(str(x) for x in sorted(r.perder_ack)))
    texto = " y ".join(perdidas) if perdidas else "nada (canal perfecto)"
    nombre = ("GO-BACK-N" if r.protocolo == "GBN" else "SELECTIVE REPEAT")
    return "\n".join([
        "", A,
        f"  {nombre}",
        f"  ventana N={r.N}   ·   {r.total} paquetes   ·   "
        f"retardo={r.retardo}   ·   timeout={r.timeout}",
        f"  se pierde: {texto}",
        A])


def mostrar(r: Resultado, con_ventana: bool = True) -> None:
    print(encabezado(r))
    print(dibujar_escalera(r))
    if con_ventana:
        print(dibujar_ventana(r))
    print(dibujar_resumen(r))
    if not r.completado:
        print("\n  (la simulación se cortó por el límite de tiempo)")


# ---------------------------------------------------------------------------
# Comparación entre los dos protocolos con el mismo escenario
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
    print("  MISMA PÉRDIDA, LOS DOS PROTOCOLOS")
    print(A)
    filas = [
        ("transmisiones de datos", gbn.transmisiones, sr.transmisiones),
        ("retransmisiones", gbn.retransmisiones, sr.retransmisiones),
        ("ACK enviados", gbn.acks_enviados, sr.acks_enviados),
        ("tiempo total", gbn.t_final, sr.t_final),
    ]
    print(f"    {'':<26} {'Go-Back-N':>12} {'Selective Repeat':>18}")
    print("    " + "-" * 58)
    for nombre, a, b in filas:
        print(f"    {nombre:<26} {a:>12} {b:>18}")
    ef_g = 100 * total / gbn.transmisiones if gbn.transmisiones else 0
    ef_s = 100 * total / sr.transmisiones if sr.transmisiones else 0
    print(f"    {'eficiencia':<26} {ef_g:>11.0f}% {ef_s:>17.0f}%")

    ahorro = gbn.transmisiones - sr.transmisiones
    print()
    if ahorro > 0:
        print(f"    Selective Repeat envió {ahorro} paquete(s) menos. Go-Back-N")
        print("    retransmitió también los que ya habían llegado bien, porque su")
        print("    receptor los descarta en vez de guardarlos en un buffer.")
    elif ahorro == 0:
        print("    Aquí empatan: no había paquetes posteriores al perdido dentro de")
        print("    la ventana, así que Go-Back-N no llegó a reenviar nada de más.")
    else:
        print(f"    Aquí gana GO-BACK-N por {-ahorro} transmisión(es), y no es un")
        print("    error: al perderse un ACK se invierte la ventaja.")
        print("    El ACK de Go-Back-N es ACUMULATIVO, así que el siguiente ACK que")
        print("    llegue ya confirma también lo que quedó sin confirmar: la pérdida")
        print("    se repara sola. En Selective Repeat cada ACK confirma un único")
        print("    paquete, así que si ese ACK se pierde no hay nada que lo cubra y")
        print("    el temporizador acaba retransmitiendo un paquete que YA había")
        print("    llegado bien.")
        print("    Resumen: SR gana cuando se pierden DATOS, GBN aguanta mejor que")
        print("    se pierdan ACK.")
    print(f"\n    Bits de secuencia mínimos:  GBN k={_min_bits(N, 'GBN')}   "
          f"SR k={_min_bits(N, 'SR')}   (para una ventana de {N})")


# ---------------------------------------------------------------------------
# Escenarios preparados y aleatorios
# ---------------------------------------------------------------------------

ESCENARIOS = [
    ("Ventana pequeña (N=2), se pierde un paquete del medio",
     dict(total=6, N=2, retardo=3, timeout=9, perder_datos={2}, perder_ack=set())),
    ("Ventana mediana (N=4), se pierde un paquete del medio",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos={2}, perder_ack=set())),
    ("Ventana grande (N=6): aquí Go-Back-N sufre de verdad",
     dict(total=10, N=6, retardo=3, timeout=12, perder_datos={1}, perder_ack=set())),
    ("Se pierde un ACK, no un paquete de datos",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos=set(), perder_ack={1})),
    ("Se pierde el PRIMER paquete: bloquea toda la ventana",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos={0}, perder_ack=set())),
    ("Se pierde el ÚLTIMO paquete de la tanda",
     dict(total=6, N=4, retardo=3, timeout=10, perder_datos={5}, perder_ack=set())),
    ("Dos pérdidas: un paquete y además su ACK",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos={2}, perder_ack={4})),
    ("Pérdida de ACK con ventana grande: aquí gana Go-Back-N",
     dict(total=10, N=6, retardo=3, timeout=10, perder_datos=set(), perder_ack={2})),
    ("Canal perfecto, sin pérdidas (la referencia)",
     dict(total=8, N=4, retardo=3, timeout=10, perder_datos=set(), perder_ack=set())),
    ("Stop-and-wait: la ventana deslizante con N=1",
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
# Interfaz
# ---------------------------------------------------------------------------

def menu(titulo: str, opciones: List[str]) -> int:
    print(f"\n{titulo}")
    for i, o in enumerate(opciones, 1):
        print(f"  {i}) {o}")
    while True:
        bruto = input("> ").strip()
        if bruto.isdigit() and 1 <= int(bruto) <= len(opciones):
            return int(bruto) - 1
        print(f"Escribe un número entre 1 y {len(opciones)}.")


def pedir_entero(texto: str, por_defecto: int, minimo: int, maximo: int) -> int:
    bruto = input(f"{texto} (Enter = {por_defecto}): ").strip()
    if not bruto:
        return por_defecto
    try:
        return max(minimo, min(int(bruto), maximo))
    except ValueError:
        return por_defecto


def a_medida() -> dict:
    print("\nArma tu propio escenario:")
    total = pedir_entero("  ¿Cuántos paquetes?", 8, 2, 20)
    N = pedir_entero("  Tamaño de la ventana N", 4, 1, total)
    retardo = pedir_entero("  Retardo de propagación", 3, 1, 8)
    timeout = pedir_entero("  Temporizador", 2 * retardo + 4, retardo + 1, 60)

    perder_datos, perder_ack = set(), set()
    idx = menu("  ¿Qué se pierde?",
               ["Un paquete de datos", "Un ACK", "Los dos", "Nada"])
    if idx in (0, 2):
        d = pedir_entero(f"  ¿Qué paquete se pierde? (0 a {total - 1}, "
                         "-1 = al azar)", -1, -1, total - 1)
        perder_datos = {random.randrange(0, total) if d < 0 else d}
    if idx in (1, 2):
        a = pedir_entero(f"  ¿Qué ACK se pierde? (0 a {total - 1}, "
                         "-1 = al azar)", -1, -1, total - 1)
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
    print("  SIMULADOR DE VENTANA DESLIZANTE  ·  Go-Back-N y Selective Repeat")
    print(A)
    print("  Dibuja el diagrama de tiempo emisor/receptor y cómo se desliza la")
    print("  ventana, para ver qué reenvía cada protocolo cuando algo se pierde.")

    while True:
        idx = menu("¿Qué quieres ver?",
                   ["Comparar los dos con un escenario preparado",
                    "Escenario al azar",
                    "Escenario a medida (elijo yo los parámetros)",
                    "Solo Go-Back-N (escenario preparado)",
                    "Solo Selective Repeat (escenario preparado)",
                    "Recorrer todos los escenarios preparados",
                    "Salir"])

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
                if input("\nEnter para el siguiente, «q» para parar: ").strip().lower() == "q":
                    break
            continue

        j = menu("Elige el escenario:", [n for n, _ in ESCENARIOS])
        cfg = ESCENARIOS[j][1]
        ejecutar(cfg, {0: "ambos", 3: "gbn", 4: "sr"}[idx])


def main() -> None:
    args = [a.lower() for a in sys.argv[1:]]
    if not args:
        interactivo()
        return
    if "--azar" in args:
        ejecutar(escenario_azar())
    elif "--comparar" in args:
        comparar(**ESCENARIOS[1][1])
    elif "--ejemplos" in args:
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
