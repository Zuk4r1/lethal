#!/usr/bin/env python3
"""
LETHAL IDOR + CSRF EXPLOITER -- v3.0 (refactor post-auditoría)

Cambios principales respecto a v2.1 (ver AUDIT.md para el detalle completo):
  1. Este archivo ahora es SOLO el CLI -- toda la lógica vive en core/ y
     se importa aquí. En v2.1 core/ existía pero nunca se importaba desde
     lethal.py (código muerto duplicado).
  2. Detección de bloqueo/vulnerable vía similarity ratio (core/detection.py)
     en vez de diff de longitud <20 / igualdad exacta de string.
  3. Concurrencia real con ThreadPoolExecutor + rate limiting adaptativo
     (core/idor.py, core/autorize.py, core/intruder.py).
  4. Sesión HTTP persistente con reintentos automáticos (core/http_client.py).
  5. Captura de evidencia cruda + generación de PoC Markdown/HTML para
     reportes de bug bounty (core/evidence.py, core/csrf.py).
  6. Patrones IDOR/CSRF externalizados a config/patterns.yaml.
"""
import argparse
import sys

from core.utils import (
    print_banner, cargar_ids, configurar_headers,
    imprimir_tabla_idor, imprimir_tabla_intruder, log_resultados,
)
from core.http_client import build_session
from core.burp_parser import extraer_idors_desde_logs, extraer_endpoints_burp_xml, parse_burp_json
from core.idor import explotar_idor
from core.autorize import autorize_advanced
from core.intruder import intruder as run_intruder
from core.csrf import detectar_csrf
from core.evidence import generar_reporte_markdown


def build_cli():
    parser = argparse.ArgumentParser(
        description="⚔️ LETHAL IDOR + CSRF Exploiter v3.0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--url", required=True, help="URL objetivo con ?param=ID o endpoint")
    parser.add_argument("--param", help="Parámetro de ID para IDOR/Autorize/Intruder")
    parser.add_argument("--ids", help="Archivo con IDs")
    parser.add_argument("--method", default="GET", help="Método HTTP")
    parser.add_argument("--header", action="append", help="Cabeceras: 'Key: Value' (repetible)")
    parser.add_argument("--alt-header", action="append",
                         help="Cabeceras alternativas (usuario/token B) para --autorize")
    parser.add_argument("--forbidden", default="Access Denied",
                         help="Texto que indica acceso denegado")
    parser.add_argument("--proxy", help="Proxy tipo http://127.0.0.1:8080 (Burp Suite)")
    parser.add_argument("--threads", type=int, default=10,
                         help="Peticiones concurrentes (nuevo en v3.0)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout por petición (segundos)")
    parser.add_argument("--silent", action="store_true", help="Sin banners, solo resultados")
    parser.add_argument("--no-evidence", action="store_true",
                         help="No guardar evidencia cruda de hallazgos (por defecto SÍ se guarda)")
    parser.add_argument("--report", action="store_true",
                         help="Generar borrador de reporte Markdown de los hallazgos vulnerables")

    parser.add_argument("--autoidor", action="store_true",
                         help="Extraer parámetros IDOR desde un log de texto (resources/burp_logs.txt)")
    parser.add_argument("--burp-logs", help="Export XML de Burp Suite")
    parser.add_argument("--burp-json", help="Export JSON de Burp Suite")
    parser.add_argument("--autorize", action="store_true", help="Modo Autorize (bypass de autorización)")
    parser.add_argument("--intruder", action="store_true", help="Modo Intruder (fuzzing de payloads)")
    parser.add_argument("--payload-list", help="Archivo con payloads para --intruder")
    return parser


def main():
    args = build_cli().parse_args()
    headers = configurar_headers(args.header)
    alt_headers = configurar_headers(args.alt_header) if args.alt_header else {}
    print_banner(args.silent)

    session = build_session(proxy=args.proxy)
    capture_evidence = not args.no_evidence

    def progreso(done, total):
        if not args.silent and total:
            sys.stdout.write(f"\r[*] Progreso: {done}/{total}")
            sys.stdout.flush()
            if done == total:
                print()

    resultados = []
    modo = None

    if args.burp_logs and args.ids:
        modo = "idor"
        id_list = cargar_ids(args.ids)
        for url, param in extraer_endpoints_burp_xml(args.burp_logs, args.silent):
            resultados.extend(explotar_idor(
                url, param, id_list, headers, args.forbidden, args.method.upper(),
                session, args.threads, args.timeout, capture_evidence, args.silent, progreso,
            ))

    elif args.burp_json and args.ids:
        modo = "idor"
        id_list = cargar_ids(args.ids)
        for url, param in parse_burp_json(args.burp_json, args.silent):
            resultados.extend(explotar_idor(
                url, param, id_list, headers, args.forbidden, args.method.upper(),
                session, args.threads, args.timeout, capture_evidence, args.silent, progreso,
            ))

    elif args.autoidor:
        modo = "idor"
        sospechosos = extraer_idors_desde_logs("resources/burp_logs.txt", args.silent)
        if not args.ids:
            print("[!] Debes proporcionar --ids para usar --autoidor")
            sys.exit(1)
        id_list = cargar_ids(args.ids)
        for param in sospechosos:
            resultados.extend(explotar_idor(
                args.url, param, id_list, headers, args.forbidden, args.method.upper(),
                session, args.threads, args.timeout, capture_evidence, args.silent, progreso,
            ))

    elif args.autorize and args.param and args.ids:
        modo = "autorize"
        id_list = cargar_ids(args.ids)
        resultados = autorize_advanced(
            args.url, args.param, id_list, headers, alt_headers, args.method.upper(),
            session, args.threads, args.timeout, capture_evidence, args.silent, progreso,
        )

    elif args.intruder and args.param and args.payload_list:
        modo = "intruder"
        with open(args.payload_list, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
        resultados = run_intruder(
            args.url, args.param, payloads, headers, args.method.upper(), session,
            args.forbidden, args.threads, args.timeout, args.silent, progreso,
        )

    elif args.param and args.ids:
        modo = "idor"
        id_list = cargar_ids(args.ids)
        resultados = explotar_idor(
            args.url, args.param, id_list, headers, args.forbidden, args.method.upper(),
            session, args.threads, args.timeout, capture_evidence, args.silent, progreso,
        )

    elif args.method.upper() in ("POST", "PUT", "DELETE", "PATCH"):
        # Sin --param/--ids: al menos corre la detección estática de CSRF
        # sobre los headers dados, en vez de exigir combos de login CSRF
        # muy específicos como hacía la v2.1.
        veredicto = detectar_csrf(args.method, headers, url=args.url)
        print(veredicto)
        sys.exit(0)

    else:
        print("[!] Debes proporcionar --param + --ids, --autoidor, --burp-logs/--burp-json, "
              "--autorize o --intruder. Ver --help.")
        sys.exit(1)

    if resultados:
        if modo == "intruder":
            tabla = imprimir_tabla_intruder(resultados, args.silent)
        else:
            id_col = "ID probado" if modo == "idor" else "ID/Payload"
            tabla = imprimir_tabla_idor(resultados, id_col, args.silent)
        log_resultados(tabla, silent=args.silent)

        vulnerables = [r for r in resultados if r.get("vulnerable")]
        if args.report and vulnerables:
            path = generar_reporte_markdown(vulnerables, modo, args.url)
            if not args.silent:
                print(f"[+] Borrador de reporte generado: {path}")


if __name__ == "__main__":
    main()
