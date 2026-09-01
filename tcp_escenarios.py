#!/usr/bin/env python3
"""
ESCENARIOS TCP ALEATORIOS  ·  SYN, ACK y ventana deslizante
===========================================================
Genera una situación TCP distinta cada vez (handshake, envío de datos, pérdidas,
ventana que se llena, cierre) y pregunta sobre ella en tres niveles:

  FÁCIL     con el diagrama delante: leer flags, ISN, números de secuencia.
  MEDIO     con el diagrama: calcular el siguiente seq/ack, ventana real, MSS.
  DIFÍCIL   SIN diagrama. Solo los parámetros escritos, y hay que deducir todo:
            números de secuencia, bytes en vuelo, ventana efectiva, qué pasa
            si algo se pierde.

El diagrama y las respuestas salen de la misma simulación, así que siempre
concuerdan.

Uso:
    python3 tcp_escenarios.py            menú interactivo
    python3 tcp_escenarios.py --facil    una ronda de ese nivel
    python3 tcp_escenarios.py --demo     muestra un escenario resuelto
"""

import random
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

A = "=" * 74
B = "-" * 74


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------

@dataclass
class Seg:
    """Un segmento TCP del intercambio."""
    n: int
    de: str               # "C" (cliente) o "S" (servidor)
    flags: str
    seq: int
    ack: Optional[int]
    datos: int            # bytes de payload
    win_campo: int        # el valor crudo del campo window
    win_real: int         # ya con la escala aplicada
    perdido: bool = False
    nota: str = ""


@dataclass
class Escenario:
    variante: str
    ip_c: str
    ip_s: str
    puerto_c: int
    puerto_s: int
    servicio: str
    isn_c: int
    isn_s: int
    mss: int
    ws_c: int
    ws_s: int
    win_c: int            # campo window crudo del cliente
    win_s: int            # campo window crudo del servidor
    cwnd: int             # ventana de congestión del cliente
    segs: List[Seg] = field(default_factory=list)
    datos_enviados: List[int] = field(default_factory=list)
    perdido_idx: Optional[int] = None
    acks_duplicados: int = 0

    # --- valores derivados que usan las preguntas ---
    @property
    def win_real_s(self) -> int:
        return self.win_s * (2 ** self.ws_s)

    @property
    def win_real_c(self) -> int:
        return self.win_c * (2 ** self.ws_c)

    @property
    def ventana_efectiva(self) -> int:
        return min(self.cwnd, self.win_real_s)

    @property
    def segmentos_en_ventana(self) -> int:
        return self.ventana_efectiva // self.mss

    def de_nombre(self, de: str) -> str:
        return "cliente" if de == "C" else "servidor"


SERVICIOS = [(80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (21, "FTP control"),
             (25, "SMTP"), (110, "POP3"), (143, "IMAP"), (3306, "MySQL")]

VARIANTES = ["handshake", "datos", "perdida", "cierre", "ventana_llena"]


# ---------------------------------------------------------------------------
# Generación del escenario
# ---------------------------------------------------------------------------

def nueva_ip() -> str:
    base = random.choice(["192.168", "10.0", "172.16"])
    if base == "10.0":
        return f"10.0.{random.randint(0, 5)}.{random.randint(2, 250)}"
    if base == "172.16":
        return f"172.16.{random.randint(0, 5)}.{random.randint(2, 250)}"
    return f"192.168.{random.randint(0, 5)}.{random.randint(2, 250)}"


def generar(nivel: str, variante: Optional[str] = None) -> Escenario:
    """Crea un escenario aleatorio y simula el intercambio completo."""
    if variante is None:
        variante = random.choice(VARIANTES)

    puerto_s, servicio = random.choice(SERVICIOS)
    # en difícil los ISN son de 32 bits de verdad; en fácil, más manejables
    if nivel == "dificil":
        isn_c = random.randint(1_000_000_000, 4_000_000_000)
        isn_s = random.randint(1_000_000_000, 4_000_000_000)
    else:
        isn_c = random.randint(10_000, 999_999)
        isn_s = random.randint(10_000, 999_999)

    e = Escenario(
        variante=variante,
        ip_c=nueva_ip(), ip_s=nueva_ip(),
        puerto_c=random.randint(32768, 60999),
        puerto_s=puerto_s, servicio=servicio,
        isn_c=isn_c, isn_s=isn_s,
        mss=random.choice([536, 1220, 1360, 1460]),
        ws_c=random.choice([0, 2, 3, 7]),
        ws_s=random.choice([0, 2, 4, 7]),
        win_c=random.choice([64240, 65535, 29200, 8192]),
        win_s=random.choice([229, 501, 502, 1024, 5840]),
        cwnd=random.choice([2, 3, 4, 6, 10]) * random.choice([536, 1460]),
    )
    simular(e)
    return e


def simular(e: Escenario) -> None:
    """Construye el intercambio paso a paso. Todo lo demás se deriva de aquí."""
    segs = e.segs
    n = 0

    def añadir(de, flags, seq, ack, datos, win_campo, escala, nota="",
               perdido=False):
        nonlocal n
        n += 1
        segs.append(Seg(n, de, flags, seq, ack, datos, win_campo,
                        win_campo * (2 ** escala), perdido, nota))
        return segs[-1]

    # ---- handshake: el SYN consume un número de secuencia ----
    añadir("C", "SYN", e.isn_c, None, 0, e.win_c, 0,
           "el window scaling aún no se aplica en el SYN")
    seq_c = e.isn_c + 1

    añadir("S", "SYN, ACK", e.isn_s, seq_c, 0, e.win_s, 0,
           "confirma el SYN del cliente con ISN+1")
    seq_s = e.isn_s + 1

    añadir("C", "ACK", seq_c, seq_s, 0, e.win_c, e.ws_c,
           "handshake completo, la conexión queda establecida")

    if e.variante == "handshake":
        return

    # ---- envío de datos del cliente ----
    if e.variante == "ventana_llena":
        cuantos = max(2, e.segmentos_en_ventana + 1)
    else:
        cuantos = random.randint(2, 4)

    tamaños = []
    for i in range(cuantos):
        if e.variante == "ventana_llena":
            tamaños.append(e.mss)
        else:
            tamaños.append(random.choice([e.mss, e.mss,
                                          random.randint(20, e.mss - 1)]))
    e.datos_enviados = tamaños

    if e.variante == "perdida":
        e.perdido_idx = random.randrange(0, len(tamaños))

    esperado_s = seq_c          # lo que el servidor espera recibir
    for i, largo in enumerate(tamaños):
        se_pierde = (e.variante == "perdida" and i == e.perdido_idx)
        añadir("C", "PSH, ACK", seq_c, seq_s, largo, e.win_c, e.ws_c,
               "SE PIERDE en la red" if se_pierde else "", se_pierde)
        seq_c += largo
        if se_pierde:
            # no llegó: el servidor ni se entera, así que no manda ningún ACK
            continue
        if seq_c - largo == esperado_s:
            esperado_s += largo
        duplicado = (e.perdido_idx is not None and i > e.perdido_idx)
        añadir("S", "ACK", seq_s, esperado_s, 0, e.win_s, e.ws_s,
               "ACK duplicado: sigue faltando el mismo byte" if duplicado else "")
        if duplicado:
            e.acks_duplicados += 1

    if e.variante == "cierre":
        añadir("C", "FIN, ACK", seq_c, seq_s, 0, e.win_c, e.ws_c,
               "el FIN también consume un número de secuencia")
        seq_c += 1
        añadir("S", "ACK", seq_s, seq_c, 0, e.win_s, e.ws_s)
        añadir("S", "FIN, ACK", seq_s, seq_c, 0, e.win_s, e.ws_s)
        seq_s += 1
        añadir("C", "ACK", seq_c, seq_s, 0, e.win_c, e.ws_c,
               "cierre completo por los dos lados")


# ---------------------------------------------------------------------------
# Presentación
# ---------------------------------------------------------------------------

def dibujar(e: Escenario, hasta: Optional[int] = None) -> str:
    """Tabla del intercambio: las columnas seq y ack alineadas dejan ver la
    progresión de un vistazo (niveles fácil y medio)."""
    segs = e.segs if hasta is None else e.segs[:hasta]
    lineas = [
        "", A,
        f"  {e.ip_c}:{e.puerto_c}  (cliente)   <-->   "
        f"{e.ip_s}:{e.puerto_s}  ({e.servicio})",
        A,
        f"   {'#':>2}  {'sentido':<10} {'flags':<10} {'seq':>11} {'ack':>11}"
        f" {'len':>5} {'win':>7}",
        "  " + "-" * 70,
    ]
    notas = []
    for x in segs:
        if x.de == "C":
            sentido = "C ══✗" if x.perdido else "C ═══►"
        else:
            sentido = "◄═══ S"
        ack = str(x.ack) if x.ack is not None else "-"
        lineas.append(
            f"   {x.n:>2}  {sentido:<10} {x.flags:<10} {x.seq:>11} {ack:>11}"
            f" {x.datos:>5} {x.win_campo:>7}")
        if x.nota:
            notas.append(f"      #{x.n}: {x.nota}")
    lineas.append("  " + "-" * 70)
    lineas.append("   C = cliente, S = servidor.  len = bytes de datos.")
    lineas.append("   win = valor CRUDO del campo window (sin aplicar la escala).")
    if notas:
        lineas.append("")
        lineas.extend(notas)
    lineas.append(A)
    return "\n".join(lineas)


def ficha(e: Escenario, con_intercambio: bool = True) -> str:
    """Solo los parámetros, en texto. Es lo que se da en nivel difícil."""
    l = [
        "", A, "  DATOS DEL ESCENARIO  (sin diagrama: hay que deducirlo)", A,
        f"    Cliente            {e.ip_c}:{e.puerto_c}",
        f"    Servidor           {e.ip_s}:{e.puerto_s}  ({e.servicio})",
        "",
        f"    ISN del cliente    {e.isn_c}",
        f"    ISN del servidor   {e.isn_s}",
        f"    MSS negociado      {e.mss} bytes",
        f"    Window scale       cliente s={e.ws_c}   servidor s={e.ws_s}",
        f"    Campo window       cliente {e.win_c}    servidor {e.win_s}",
        f"    cwnd del cliente   {e.cwnd} bytes",
    ]
    if con_intercambio and e.datos_enviados:
        l += ["",
              "    Tras completar el handshake, el cliente envía en orden "
              "segmentos de:",
              "      " + ", ".join(f"{x} bytes" for x in e.datos_enviados)]
        if e.perdido_idx is not None:
            l.append(f"    El segmento número {e.perdido_idx + 1} de esa lista "
                     "SE PIERDE en la red;")
            l.append("    los demás llegan bien.")
    if e.variante == "cierre":
        l.append("    Al terminar, el cliente cierra la conexión con un FIN.")
    l.append(A)
    return "\n".join(l)


# ---------------------------------------------------------------------------
# Motor de preguntas
# ---------------------------------------------------------------------------

@dataclass
class Pregunta:
    enunciado: str
    respuesta: Any
    explicacion: str
    tipo: str = "num"          # "num" | "texto" | "opcion"
    opciones: List[str] = field(default_factory=list)


def _num(texto: str) -> Optional[int]:
    t = str(texto).strip().lower().replace(" ", "").replace(",", "").replace("_", "")
    if t.startswith("0x"):
        try:
            return int(t[2:], 16)
        except ValueError:
            return None
    try:
        return int(t)
    except ValueError:
        return None


def acierta(dado: str, p: Pregunta) -> bool:
    if p.tipo == "num":
        n = _num(dado)
        return n is not None and n == int(p.respuesta)
    if p.tipo == "opcion":
        letras = "ABCDEFGH"
        d = dado.strip().upper()
        return d in letras[:len(p.opciones)] and letras.index(d) == p.respuesta
    limpio = " ".join(dado.strip().lower().split())
    esperado = " ".join(str(p.respuesta).strip().lower().split())
    limpio = re.sub(r"[^a-z0-9]", "", limpio)
    esperado = re.sub(r"[^a-z0-9]", "", esperado)
    return limpio == esperado


def _opcion(correcta: str, otras: List[str]) -> Tuple[List[str], int]:
    opts = [correcta] + [x for x in otras if x != correcta][:3]
    random.shuffle(opts)
    return opts, opts.index(correcta)


# ---------------------------------------------------------------------------
# FÁCIL: leer el diagrama
# ---------------------------------------------------------------------------

def preguntas_faciles(e: Escenario) -> List[Pregunta]:
    qs = []
    syn, synack, ack = e.segs[0], e.segs[1], e.segs[2]

    qs.append(Pregunta(
        "¿Cuál es el ISN (número de secuencia inicial) del cliente?",
        e.isn_c,
        f"Es el seq del primer paquete, el SYN: {e.isn_c}. Se elige al azar "
        "justamente para que un atacante no pueda predecirlo e inyectar datos "
        "en la conexión."))

    qs.append(Pregunta(
        "¿Qué número de ACK manda el servidor en su SYN-ACK (segmento #2)?",
        synack.ack,
        f"{e.isn_c} + 1 = {synack.ack}. El SYN no lleva ni un byte de datos, "
        "pero CONSUME un número de secuencia, así que el siguiente byte que el "
        f"servidor espera es el {synack.ack}."))

    opts, idx = _opcion(
        "El SYN consume un número de secuencia aunque no lleve datos",
        ["El servidor añade 1 byte de relleno",
         "Es un error de Wireshark al mostrar números relativos",
         "El +1 corresponde a la cabecera TCP"])
    qs.append(Pregunta(
        "¿Por qué el ACK del SYN-ACK es ISN+1 y no ISN, si el SYN no lleva datos?",
        idx, "El SYN y el FIN son las dos banderas que consumen un número de "
             "secuencia sin transportar datos. Por eso el handshake avanza la "
             "numeración en 1 y el cierre también.",
        tipo="opcion", opciones=opts))

    qs.append(Pregunta(
        "¿Qué flags lleva el segmento #2?",
        "SYN ACK",
        "Es el SYN-ACK: el servidor acepta la conexión (SYN) y a la vez "
        "confirma el SYN del cliente (ACK). Es el único segmento del handshake "
        "que lleva las dos.",
        tipo="texto"))

    qs.append(Pregunta(
        "¿Cuántos segmentos ocupa el handshake, antes de que viaje el primer "
        "byte de datos?",
        3, "SYN, SYN-ACK y ACK: el three-way handshake. La conexión queda "
           "establecida al enviarse el tercero; los datos pueden empezar a "
           "partir de ahí."))

    qs.append(Pregunta(
        f"¿Qué valor tiene el campo window en el SYN del cliente (segmento #1)?",
        e.win_c,
        f"El campo vale {e.win_c}. Ojo: en el SYN el window scaling todavía NO "
        "se aplica, porque la opción se está negociando justo en ese paquete. "
        "La escala solo vale para los segmentos posteriores."))

    qs.append(Pregunta(
        "¿En qué número de secuencia empieza a numerar el cliente sus BYTES de "
        f"datos, una vez completado el handshake?",
        e.isn_c + 1,
        f"{e.isn_c} + 1 = {e.isn_c + 1}. El ISN se gastó en el SYN, así que el "
        "primer byte de datos real lleva el número siguiente. Ese es el seq que "
        "ves en el ACK del handshake (segmento #3)."))

    datos = [x for x in e.segs if x.datos > 0 and not x.perdido]
    if datos:
        d = datos[0]
        qs.append(Pregunta(
            f"¿Cuántos bytes de datos transporta el segmento #{d.n}?",
            d.datos,
            f"La columna len lo dice: {d.datos} bytes. Un segmento con len=0 es "
            "puro control (un ACK, un SYN o un FIN); los que llevan datos son "
            "los que hacen avanzar el número de secuencia."))
    return qs


# ---------------------------------------------------------------------------
# MEDIO: calcular sobre el diagrama
# ---------------------------------------------------------------------------

def preguntas_medias(e: Escenario) -> List[Pregunta]:
    qs = []

    qs.append(Pregunta(
        f"El servidor negoció window scale s={e.ws_s} y anuncia el campo "
        f"window={e.win_s} después del handshake. ¿Cuántos BYTES de ventana son "
        "en realidad?",
        e.win_real_s,
        f"{e.win_s} x 2^{e.ws_s} = {e.win_s} x {2 ** e.ws_s} = {e.win_real_s} "
        "bytes. El campo window es de 16 bits, así que sin la escala no se "
        "podría anunciar más de 65535."))

    qs.append(Pregunta(
        f"Con esa ventana real del servidor ({e.win_real_s} bytes) y un MSS de "
        f"{e.mss}, ¿cuántos segmentos LLENOS puede tener el cliente en vuelo "
        "antes de quedarse sin ventana?",
        e.win_real_s // e.mss,
        f"{e.win_real_s} // {e.mss} = {e.win_real_s // e.mss} segmentos "
        "completos. Es el mismo razonamiento que el tamaño N de una ventana "
        "deslizante, solo que TCP la mide en bytes en vez de en paquetes."))

    datos = [x for x in e.segs if x.datos > 0 and not x.perdido]
    if datos:
        d = datos[0]
        # la respuesta se toma de la simulación: si antes se perdió algo, el ACK
        # NO es seq+len, sino que se queda clavado en el hueco
        i = e.segs.index(d)
        real = next((x.ack for x in e.segs[i + 1:] if x.de == "S"), None)
        if real is not None:
            hay_hueco = (real != d.seq + d.datos)
            if hay_hueco:
                explica = (
                    f"Cuidado, aquí NO es {d.seq} + {d.datos} = "
                    f"{d.seq + d.datos}. Antes de este segmento se perdió otro, "
                    f"así que el servidor sigue esperando el byte {real} y no "
                    "puede confirmar más allá del hueco: el ACK de TCP es "
                    "ACUMULATIVO. Guardará este segmento en su buffer, pero "
                    f"repetirá ACK {real} hasta que le llegue lo que falta.")
            else:
                explica = (
                    f"{d.seq} + {d.datos} = {real}. El ACK indica el SIGUIENTE "
                    "byte que se espera, no el último recibido, y al ser "
                    "acumulativo confirma implícitamente todo lo anterior.")
            qs.append(Pregunta(
                f"El segmento #{d.n} sale con seq={d.seq} y len={d.datos}. "
                "¿Qué número de ACK devolverá el servidor al recibirlo?",
                real, explica))
        siguiente_seq = d.seq + d.datos
        qs.append(Pregunta(
            f"¿Con qué número de secuencia saldrá el SIGUIENTE segmento de "
            f"datos del cliente, después del #{d.n}?",
            siguiente_seq,
            f"{d.seq} + {d.datos} = {siguiente_seq}. El emisor numera los bytes "
            "que va mandando, y eso NO depende de lo que le confirmen: aunque "
            "un segmento anterior se haya perdido, el seq del cliente sigue "
            "avanzando igual. Lo que se queda atrás en ese caso es el ACK del "
            "receptor, no el seq del emisor."))

    total_datos = sum(x.datos for x in e.segs if x.de == "C")
    if total_datos:
        entregados = sum(x.datos for x in e.segs if x.de == "C" and not x.perdido)
        qs.append(Pregunta(
            "Sumando todos los segmentos del cliente, ¿cuántos bytes de datos "
            "intentó enviar en total (contando también los que se perdieron)?",
            total_datos,
            f"{' + '.join(str(x.datos) for x in e.segs if x.de == 'C' and x.datos)}"
            f" = {total_datos} bytes."
            + (f" De esos, solo {entregados} llegaron al servidor."
               if entregados != total_datos else "")))

    qs.append(Pregunta(
        f"La cwnd del cliente es {e.cwnd} bytes y la ventana real anunciada por "
        f"el servidor es {e.win_real_s}. ¿Cuántos bytes puede tener el cliente "
        "en vuelo como máximo?",
        e.ventana_efectiva,
        f"min(cwnd, rwnd) = min({e.cwnd}, {e.win_real_s}) = "
        f"{e.ventana_efectiva} bytes. Mandan las dos a la vez: rwnd protege al "
        "RECEPTOR de desbordarse y cwnd protege a la RED de congestionarse. La "
        "que sea más pequeña es la que frena."
        + (" Aquí el cuello de botella es la ventana del receptor."
           if e.win_real_s < e.cwnd else
           " Aquí el cuello de botella es la congestión.")))

    opts, idx = _opcion(
        "En el campo window de la cabecera TCP",
        ["En una opción TCP negociada en el handshake",
         "En el campo urgent pointer",
         "En ningún sitio: cwnd nunca se transmite, es interna del emisor"])
    qs.append(Pregunta(
        "¿Dónde viaja la ventana de recepción (rwnd) dentro del paquete?",
        idx,
        "rwnd es el campo window, 2 bytes de la cabecera TCP, y se puede leer "
        "en cualquier volcado. cwnd en cambio es una variable interna del "
        "emisor: no se transmite y jamás la verás en una captura.",
        tipo="opcion", opciones=opts))

    if e.perdido_idx is not None:
        dups = [x for x in e.segs if x.de == "S" and "duplicado" in x.nota]
        if dups:
            qs.append(Pregunta(
                "El servidor repite el mismo número de ACK varias veces. ¿Qué "
                "valor repite?",
                dups[0].ack,
                f"Repite ACK {dups[0].ack}, que es el byte que le falta. Aunque "
                "sigan llegando segmentos posteriores, el ACK acumulativo no "
                "puede avanzar más allá del hueco: se queda clavado ahí. Esos "
                "ACK repetidos son los ACK DUPLICADOS."))
            qs.append(Pregunta(
                "¿Cuántos ACK duplicados manda el servidor en este intercambio?",
                e.acks_duplicados,
                f"{e.acks_duplicados}. Cada segmento que llega después del hueco "
                "provoca uno. Cuando el emisor recibe 3 ACK duplicados, no "
                "espera a que venza el temporizador: retransmite de inmediato "
                "el segmento que falta. Eso es la RETRANSMISIÓN RÁPIDA."))
    return qs


# ---------------------------------------------------------------------------
# DIFÍCIL: sin diagrama, solo con los parámetros
# ---------------------------------------------------------------------------

def preguntas_dificiles(e: Escenario) -> List[Pregunta]:
    """Todo se deduce de la ficha de parámetros: no se muestra el intercambio."""
    qs = []
    tras_handshake_c = e.isn_c + 1
    tras_handshake_s = e.isn_s + 1

    qs.append(Pregunta(
        "Sin mirar ningún diagrama: ¿qué par (seq, ack) lleva el TERCER "
        "segmento del handshake, el ACK que manda el cliente? Responde solo el "
        "seq.",
        tras_handshake_c,
        f"seq = ISN_cliente + 1 = {e.isn_c} + 1 = {tras_handshake_c}, porque el "
        f"SYN consumió un número. Y su ack sería ISN_servidor + 1 = "
        f"{tras_handshake_s}, por el mismo motivo con el SYN del servidor."))

    qs.append(Pregunta(
        "¿Y qué número de ACK lleva ese mismo tercer segmento del handshake?",
        tras_handshake_s,
        f"ISN_servidor + 1 = {e.isn_s} + 1 = {tras_handshake_s}. El handshake es "
        "simétrico: cada lado consume un número con su SYN y el otro lo "
        "confirma sumándole uno."))

    if e.datos_enviados:
        # seq del k-ésimo segmento de datos, contando solo lo ya enviado antes
        k = min(len(e.datos_enviados), random.randint(2, len(e.datos_enviados)))
        previos = sum(e.datos_enviados[:k - 1])
        seq_k = tras_handshake_c + previos
        suma = " + ".join(str(x) for x in e.datos_enviados[:k - 1]) or "0"
        qs.append(Pregunta(
            f"El cliente envía en orden los segmentos de la lista. ¿Con qué "
            f"número de secuencia sale el segmento número {k} de esa lista?",
            seq_k,
            f"Al primero le toca {tras_handshake_c} (ISN+1). Antes del "
            f"segmento {k} se enviaron {suma} = {previos} bytes, así que su seq "
            f"es {tras_handshake_c} + {previos} = {seq_k}. Recuerda que TCP "
            "numera bytes, no segmentos: el seq salta tantas unidades como "
            "bytes vayan delante."))

        total = sum(e.datos_enviados)
        if e.perdido_idx is None:
            final = tras_handshake_c + total
            qs.append(Pregunta(
                "Si todos los segmentos llegan bien, ¿qué número de ACK "
                "devolverá el servidor justo después de recibir el ÚLTIMO "
                "segmento de datos?",
                final,
                f"{tras_handshake_c} + {total} = {final}. Es el número del "
                "siguiente byte que esperaría, con todos los datos confirmados."
                + (" Cuidado: si después llega un FIN, el ACK subirá otra "
                   "unidad más, porque el FIN también consume un número de "
                   "secuencia." if e.variante == "cierre" else "")))
        else:
            hasta = sum(e.datos_enviados[:e.perdido_idx])
            atascado = tras_handshake_c + hasta
            qs.append(Pregunta(
                f"El segmento número {e.perdido_idx + 1} de la lista se pierde y "
                "los demás llegan bien. ¿En qué número de ACK se queda atascado "
                "el servidor?",
                atascado,
                f"En {atascado}: es el primer byte que le falta. El ACK de TCP "
                "es ACUMULATIVO, así que aunque le lleguen los segmentos "
                "posteriores no puede confirmar más allá del hueco. Los "
                "guardará en su buffer (como haría Selective Repeat), pero "
                "seguirá repitiendo ese mismo ACK."))
            posteriores = len(e.datos_enviados) - e.perdido_idx - 1
            qs.append(Pregunta(
                "¿Cuántos ACK DUPLICADOS generará esa pérdida?",
                posteriores,
                f"Uno por cada segmento que llegue después del hueco: "
                f"{posteriores}. Del segmento perdido no llega nada, así que no "
                "genera ACK ninguno."
                + (" Con 3 o más, el emisor haría retransmisión rápida sin "
                   "esperar el temporizador." if posteriores >= 3 else
                   " Hacen falta 3 para disparar la retransmisión rápida, así "
                   "que aquí habría que esperar a que venza el temporizador.")))

    qs.append(Pregunta(
        f"El servidor tiene window scale s={e.ws_s} y su campo window vale "
        f"{e.win_s} en los segmentos posteriores al handshake. ¿Cuántos bytes "
        "de ventana real anuncia?",
        e.win_real_s,
        f"{e.win_s} x 2^{e.ws_s} = {e.win_real_s} bytes. Sin haber capturado el "
        "handshake sería imposible saberlo: el factor de escala solo viaja ahí."))

    qs.append(Pregunta(
        f"Con cwnd={e.cwnd} y esa ventana del receptor, y un MSS de {e.mss}: "
        "¿cuántos segmentos LLENOS puede tener el cliente sin confirmar antes "
        "de tener que detenerse?",
        e.segmentos_en_ventana,
        f"La ventana efectiva es min({e.cwnd}, {e.win_real_s}) = "
        f"{e.ventana_efectiva} bytes, y {e.ventana_efectiva} // {e.mss} = "
        f"{e.segmentos_en_ventana} segmentos completos. Es exactamente el "
        "parámetro N de una ventana deslizante, expresado en bytes."))

    if e.datos_enviados:
        acumulado = 0
        bloquea_en = None
        for i, x in enumerate(e.datos_enviados, 1):
            acumulado += x
            if acumulado > e.ventana_efectiva:
                bloquea_en = i
                break
        if bloquea_en:
            previo = sum(e.datos_enviados[:bloquea_en - 1])
            qs.append(Pregunta(
                "Suponiendo que NO llega ningún ACK mientras tanto: ¿cuántos "
                "segmentos de la lista alcanza a enviar el cliente antes de "
                "quedarse sin ventana?",
                bloquea_en - 1,
                f"Con {e.ventana_efectiva} bytes de ventana efectiva, tras "
                f"{bloquea_en - 1} segmentos lleva {previo} bytes en vuelo; el "
                f"siguiente ({e.datos_enviados[bloquea_en - 1]} bytes) se "
                f"pasaría de {e.ventana_efectiva}, así que el cliente se "
                "detiene y espera un ACK que deslice la ventana. Eso es "
                "exactamente el bloqueo por ventana llena."))
        else:
            qs.append(Pregunta(
                "Suponiendo que NO llega ningún ACK mientras tanto: ¿cuántos "
                "segmentos de la lista alcanza a enviar el cliente antes de "
                "quedarse sin ventana?",
                len(e.datos_enviados),
                f"Los {len(e.datos_enviados)}: en total son "
                f"{sum(e.datos_enviados)} bytes y la ventana efectiva es "
                f"{e.ventana_efectiva}, así que caben todos sin bloquearse."))

    if e.variante == "cierre":
        total = sum(e.datos_enviados)
        seq_fin = tras_handshake_c + total
        qs.append(Pregunta(
            "Después de enviar todos los datos, el cliente manda un FIN. ¿Con "
            "qué número de secuencia sale ese FIN?",
            seq_fin,
            f"{tras_handshake_c} + {total} = {seq_fin}: va justo después del "
            "último byte de datos."))
        qs.append(Pregunta(
            "¿Y con qué número de ACK responde el servidor a ese FIN?",
            seq_fin + 1,
            f"{seq_fin} + 1 = {seq_fin + 1}. El FIN, igual que el SYN, consume "
            "un número de secuencia aunque no lleve datos. Son las dos únicas "
            "banderas que lo hacen."))

    opts, idx = _opcion(
        "Tres ACK duplicados seguidos",
        ["Un único ACK duplicado",
         "Que venza el temporizador de retransmisión",
         "Que la ventana del receptor llegue a cero"])
    qs.append(Pregunta(
        "¿Qué dispara la RETRANSMISIÓN RÁPIDA en TCP, sin esperar al "
        "temporizador?",
        idx,
        "Tres ACK duplicados. La idea es que si siguen llegando ACK repetidos "
        "es porque los segmentos posteriores SÍ están llegando: la red no está "
        "caída, solo se perdió uno. Esperar el temporizador entero sería "
        "desperdiciar tiempo.",
        tipo="opcion", opciones=opts))

    opts, idx = _opcion(
        "Detenerse y mandar sondas periódicas (window probes) hasta que se "
        "anuncie espacio",
        ["Cerrar la conexión con un RST",
         "Seguir enviando a la mitad de la velocidad",
         "Retransmitir toda la ventana desde el principio"])
    qs.append(Pregunta(
        "Si el servidor llegara a anunciar window=0, ¿qué debe hacer el cliente?",
        idx,
        "window=0 significa que el buffer del receptor está lleno. El emisor "
        "para; y para no quedarse bloqueado para siempre si se pierde el "
        "anuncio de reapertura, manda sondas periódicas preguntando si ya hay "
        "sitio.",
        tipo="opcion", opciones=opts))

    return qs


GENERADORES = {
    "facil": preguntas_faciles,
    "medio": preguntas_medias,
    "dificil": preguntas_dificiles,
}


# ---------------------------------------------------------------------------
# Ronda de juego
# ---------------------------------------------------------------------------

ETIQUETA = {"facil": "FÁCIL", "medio": "MEDIO", "dificil": "DIFÍCIL"}


def contexto(e: Escenario, nivel: str) -> str:
    """Fácil y medio ven el intercambio; difícil solo los parámetros."""
    if nivel == "dificil":
        return ficha(e)
    return dibujar(e) + "\n" + resumen_parametros(e)


def resumen_parametros(e: Escenario) -> str:
    return "\n".join([
        f"   MSS negociado {e.mss}   ·   window scale: cliente s={e.ws_c}, "
        f"servidor s={e.ws_s}",
        f"   cwnd del cliente {e.cwnd} bytes",
        ""])


def ronda(nivel: str, cuantas: int = 6,
          variante: Optional[str] = None) -> Tuple[int, int]:
    e = generar(nivel, variante)
    qs = GENERADORES[nivel](e)
    random.shuffle(qs)
    qs = qs[:cuantas]

    print(contexto(e, nivel))
    if nivel == "dificil":
        print("  Sin diagrama: todo hay que deducirlo de los datos de arriba.\n")

    aciertos = 0
    for i, q in enumerate(qs, 1):
        print(B)
        print(f"[{ETIQUETA[nivel]}]  Pregunta {i}/{len(qs)}")
        print(f"  {q.enunciado}")
        if q.tipo == "opcion":
            for j, o in enumerate(q.opciones):
                print(f"    {'ABCDEFGH'[j]}) {o}")
            dado = input("  Tu respuesta (letra): ")
        else:
            dado = input("  Tu respuesta: ")
        if acierta(dado, q):
            print("  >> Correcto.")
            aciertos += 1
        else:
            if q.tipo == "opcion":
                correcta = f"{'ABCDEFGH'[q.respuesta]}) {q.opciones[q.respuesta]}"
            else:
                correcta = q.respuesta
            print(f"  >> Incorrecto. Respuesta: {correcta}")
        print(f"     {q.explicacion}")

    print("\n" + A)
    print(f"  {aciertos}/{len(qs)} en nivel {ETIQUETA[nivel]}")
    print(A)
    if nivel == "dificil" and aciertos < len(qs):
        print("\n  Así era el intercambio en realidad:")
        print(dibujar(e))
    return aciertos, len(qs)


def menu(titulo: str, opciones: List[str]) -> int:
    print(f"\n{titulo}")
    for i, o in enumerate(opciones, 1):
        print(f"  {i}) {o}")
    while True:
        bruto = input("> ").strip()
        if bruto.isdigit() and 1 <= int(bruto) <= len(opciones):
            return int(bruto) - 1
        print(f"Escribe un número entre 1 y {len(opciones)}.")


def interactivo() -> None:
    print(A)
    print("  ESCENARIOS TCP ALEATORIOS  ·  SYN, ACK y ventana deslizante")
    print(A)
    print("  Cada ronda genera una situación distinta: handshake, envío de")
    print("  datos, una pérdida, la ventana llenándose o el cierre.")
    print("  En FÁCIL y MEDIO ves el intercambio; en DIFÍCIL solo los")
    print("  parámetros, y tienes que deducir los números tú.")

    total_ok = total_q = 0
    while True:
        idx = menu("¿Qué nivel?",
                   ["Fácil    (con diagrama: leer flags, ISN, seq y ack)",
                    "Medio    (con diagrama: calcular seq/ack, ventana, MSS)",
                    "Difícil  (SIN diagrama: solo los parámetros)",
                    "Los tres niveles seguidos, con el mismo tipo de escenario",
                    "Salir"])
        if idx == 4:
            break
        if idx == 3:
            variante = random.choice(VARIANTES)
            for niv in ("facil", "medio", "dificil"):
                a, b = ronda(niv, 4, variante)
                total_ok += a
                total_q += b
        else:
            niv = ["facil", "medio", "dificil"][idx]
            a, b = ronda(niv, 6)
            total_ok += a
            total_q += b

    if total_q:
        print(f"\nTotal de la sesión: {total_ok}/{total_q} "
              f"({100 * total_ok / total_q:.0f}%)")


def main() -> None:
    args = [a.lower().lstrip("-") for a in sys.argv[1:]]
    if not args:
        interactivo()
        return
    if "demo" in args:
        e = generar("medio")
        print(dibujar(e))
        print(ficha(e))
        for nivel in ("facil", "medio", "dificil"):
            print(f"\n{B}\n  Preguntas de nivel {ETIQUETA[nivel]}\n{B}")
            for q in GENERADORES[nivel](e):
                if q.tipo == "opcion":
                    correcta = q.opciones[q.respuesta]
                else:
                    correcta = q.respuesta
                print(f"\n  · {q.enunciado}")
                print(f"    -> {correcta}")
        return
    for nivel in ("facil", "medio", "dificil"):
        if nivel in args or nivel[:4] in args:
            ronda(nivel)
            return
    print(__doc__)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n")
