# Analizador de tráfico de red

Herramienta en Python que analiza capturas de red (`.pcap`) o tráfico en directo, resume qué está pasando en la red y detecta dos técnicas de reconocimiento: **escaneos de puertos** (SYN scan, como `nmap -sS`) y **barridos de ping** (ping sweep, como `nmap -sn`).

> **EN:** Python tool that analyzes network captures or live traffic, summarizes protocols and top talkers, and detects TCP SYN port scans and ICMP ping sweeps using a sliding time window.

## Qué hace

- Lee ficheros `.pcap` / `.pcapng` (por ejemplo, exportados desde Wireshark) o captura en directo.
- Calcula estadísticas: reparto de protocolos (TCP, UDP, ICMP), IPs que más tráfico envían y puertos TCP más usados.
- Detecta escaneos de puertos: si una IP envía paquetes SYN sin ACK a **15 o más puertos distintos** de un mismo destino en **menos de 10 segundos**, genera una alerta. Ambos valores son configurables.
- Detecta barridos de ping: si una IP envía pings (ICMP Echo Request) a **15 o más IPs distintas** en **menos de 10 segundos**, genera una alerta.
- Genera un informe en Markdown.

## Cómo funciona la detección

En un escaneo SYN, el atacante envía el primer paquete del *three-way handshake* (SYN) a muchos puertos para ver cuáles responden. El tráfico normal, en cambio, se concentra en pocos puertos (443, 80, 53…).

El detector agrupa los SYN por pareja `(origen, destino)` y mantiene una **ventana deslizante** con los puertos sondeados en los últimos N segundos. Si el número de puertos distintos supera el umbral, se marca como escaneo. Los SYN-ACK (respuestas del servidor) se ignoran para no generar falsos positivos.

En un barrido de ping, el atacante hace ping a muchas IPs de la red para descubrir qué equipos están encendidos. El detector usa la misma ventana deslizante, pero agrupa por IP de origen y cuenta **IPs de destino distintas**. Solo cuentan las peticiones (ICMP tipo 8), no las respuestas (tipo 0), y hacer muchos pings a un mismo equipo no se considera barrido.

## Instalación

Requiere Python 3.10 o superior.

```bash
git clone https://github.com/Pitsaraa/analizador-trafico.git
cd analizador-trafico
python -m venv .venv
.venv\Scripts\activate        # En Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

Probarlo con una captura de ejemplo, que se genera en memoria sin enviar nada a la red:

```bash
python generar_demo.py
python -m analizador demo.pcap
```

Analizar una captura propia de Wireshark y guardar el informe:

```bash
python -m analizador mi_captura.pcapng -o informe.md
```

Capturar en directo (en Windows requiere [Npcap](https://npcap.com/), que es gratuito; en Linux, ejecutar con `sudo`):

```bash
python -m analizador --vivo -c 1000
```

Ajustar la sensibilidad del detector:

```bash
python -m analizador demo.pcap --umbral 20 --ventana 5
```

El programa devuelve el código de salida `1` si encuentra alertas, para poder usarlo en scripts.

## Ejemplo de informe

| Origen | Destino | Inicio | Puertos sondeados |
|---|---|---|---|
| 192.168.1.66 | 192.168.1.20 | 2026-05-28 20:27:00 UTC | 1–100 (100 puertos) |

| Origen | Inicio | Equipos sondeados |
|---|---|---|
| 192.168.1.77 | 2026-05-28 20:27:20 UTC | 50 |

## Tests

```bash
pip install pytest
python -m pytest
```

## Estructura

```
analizador/
  detector.py   # Estadísticas y detección de escaneos y barridos de ping
  informe.py    # Generación del informe en Markdown
  __main__.py   # Interfaz de línea de comandos
generar_demo.py # Crea una captura de ejemplo con un escaneo y un barrido simulados
tests/          # Tests con paquetes construidos con Scapy
```

## Próximas mejoras

- Detectar escaneos UDP.
- Exportar las alertas a JSON.

## Aviso

Captura y analiza solo tráfico de redes propias o en las que tengas autorización.

## Autor

Álvaro Romero Cabeza de Vaca, estudiante de Ingeniería Telemática en la Universidad de Málaga. [LinkedIn](https://www.linkedin.com/in/alvaroromerocabeza/)
