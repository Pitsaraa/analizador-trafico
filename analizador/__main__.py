"""Uso:
    python -m analizador captura.pcap [-o informe.md]
    python -m analizador --vivo [-i interfaz] [-c 500]
"""

import argparse
import sys

from scapy.all import rdpcap, sniff

from .detector import analyze
from .informe import to_markdown


def main(argv=None):
    parser = argparse.ArgumentParser(prog="analizador", description="Analiza tráfico de red y detecta escaneos de puertos y barridos de ping.")
    parser.add_argument("pcap", nargs="?", help="fichero .pcap/.pcapng a analizar")
    parser.add_argument("--vivo", action="store_true", help="capturar en directo (requiere Npcap/root)")
    parser.add_argument("-i", "--interfaz", help="interfaz de red para la captura en directo")
    parser.add_argument("-c", "--cantidad", type=int, default=500, help="paquetes a capturar en directo (por defecto 500)")
    parser.add_argument("--umbral", type=int, default=15, help="puertos o IPs distintos para considerar escaneo o barrido (por defecto 15)")
    parser.add_argument("--ventana", type=float, default=10.0, help="ventana de tiempo en segundos (por defecto 10)")
    parser.add_argument("-o", "--salida", help="guardar el informe en este fichero Markdown")
    args = parser.parse_args(argv)

    if args.vivo:
        print(f"Capturando {args.cantidad} paquetes...", file=sys.stderr)
        packets = sniff(iface=args.interfaz, count=args.cantidad)
        origen = f"captura en directo ({args.interfaz or 'interfaz por defecto'})"
    elif args.pcap:
        packets = rdpcap(args.pcap)
        origen = args.pcap
    else:
        parser.error("indica un fichero .pcap o usa --vivo")

    report = analyze(packets, threshold=args.umbral, window=args.ventana)
    markdown = to_markdown(report, origen)

    if args.salida:
        with open(args.salida, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"Informe guardado en {args.salida}", file=sys.stderr)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(markdown)

    return 1 if report.alerts or report.sweeps else 0


if __name__ == "__main__":
    sys.exit(main())
