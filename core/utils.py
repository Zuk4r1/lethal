"""Utilidades compartidas: banner, carga de archivos, impresión de tabla."""
import os

from colorama import Fore, init
from prettytable import PrettyTable

init(autoreset=True)


def print_banner(silent=False):
    if silent:
        return
    banner = r"""
           _      _____ _______ _    _          _
          | |    | ____|__   __| |  | |   /\   | |
          | |    | |__    | |  | |__| |  /  \  | |
          | |    |  __|   | |  |  __  | / /\ \ | |
          | |____| |____  | |  | |  | |/ ____ \| |____
          |______|______| |_|  |_|  |_/_/    \_\______|

          LETHAL IDOR + CSRF EXPLOITER -- v3.0 (refactor) ⚔️
   🐉 Autor: @Zuk4r1 | github.com/Zuk4r1 | BugBounty/RedTeam Edition
    """
    print(Fore.LIGHTRED_EX + banner + Fore.RESET)


def cargar_ids(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def configurar_headers(cabeceras):
    headers = {}
    if cabeceras:
        for h in cabeceras:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def imprimir_tabla_idor(resultados, id_col="ID probado", silent=False):
    """Tabla para resultados de IDOR/Autorize (comparten forma: id/payload,
    status, desc, vulnerable, similitud opcional)."""
    tabla = PrettyTable([id_col, "Resultado", "Similitud", "Descripción", "¿Vulnerable?"])
    tabla.align["Descripción"] = "l"
    resultados_ordenados = sorted(resultados, key=lambda r: not r.get("vulnerable", False))
    for r in resultados_ordenados:
        sim = r.get("similitud")
        sim_str = f"{sim*100:.1f}%" if isinstance(sim, (int, float)) else "-"
        clave_id = r.get("id", r.get("payload", ""))
        tabla.add_row([clave_id, r.get("status"), sim_str, r.get("desc", ""),
                       "Sí" if r.get("vulnerable") else "No"])
    if not silent:
        print(tabla)
    return tabla


def imprimir_tabla_intruder(resultados, silent=False):
    tabla = PrettyTable(["Payload", "Resultado", "Similitud", "Descripción", "¿Vulnerable?"])
    tabla.align["Descripción"] = "l"
    resultados_ordenados = sorted(resultados, key=lambda r: not r.get("vulnerable", False))
    for r in resultados_ordenados:
        sim = r.get("similitud")
        sim_str = f"{sim*100:.1f}%" if isinstance(sim, (int, float)) else "-"
        tabla.add_row([r.get("payload"), r.get("status"), sim_str, r.get("desc", ""),
                       "Sí" if r.get("vulnerable") else "No"])
    if not silent:
        print(tabla)
    return tabla


def log_resultados(tabla, archivo="output/resultados.txt", silent=False):
    os.makedirs(os.path.dirname(archivo), exist_ok=True)
    with open(archivo, "w") as f:
        f.write(tabla.get_string())
    if not silent:
        print(f"{Fore.YELLOW}[+] Resultados guardados en: {archivo}")
