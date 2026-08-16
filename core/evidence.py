"""
Captura de evidencia y generación de PoC.

La v2.1 solo escribía una tabla PrettyTable a texto plano -- para armar un
reporte en HackerOne/Bugcrowd había que reproducir cada hallazgo a mano
para conseguir el request/response completo. Este módulo guarda la
evidencia cruda de cada hallazgo vulnerable y genera un borrador de
reporte en Markdown con la estructura Title/Summary/Steps to
reproduce/Impact/Severity/Recommendation.
"""
import json
import os
import re
import time
from datetime import datetime, timezone


def _slug(texto, max_len=40):
    return re.sub(r"\W+", "_", str(texto)).strip("_")[:max_len]


def guardar_evidencia(hallazgo: dict, request_info: dict, response_info: dict,
                       outdir="output/evidence"):
    """
    Guarda un JSON con la evidencia completa de un hallazgo vulnerable:
    request (método, url, headers, body) y response (status, headers,
    body truncado a 5000 chars para no inflar el output con blobs).
    """
    os.makedirs(outdir, exist_ok=True)
    timestamp = int(time.time() * 1000)
    slug = _slug(hallazgo.get("id") or hallazgo.get("payload") or "hallazgo")
    path = os.path.join(outdir, f"{timestamp}_{slug}.json")

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hallazgo": hallazgo,
        "request": request_info,
        "response": {
            "status": response_info.get("status"),
            "headers": response_info.get("headers"),
            "body": (response_info.get("body") or "")[:5000],
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return path


SEVERITY_BY_TYPE = {
    "idor": "High",
    "autorize": "Critical",
    "csrf": "Medium",
    "intruder": "Informational",  # requiere validación manual, ver nota
}


def generar_reporte_markdown(hallazgos_vulnerables, tipo, target_url, outdir="output"):
    """
    Genera un borrador de reporte en Markdown a partir de los hallazgos
    marcados como vulnerable=True, con la estructura que piden las
    plataformas de bug bounty. Esto es un BORRADOR: siempre valida
    manualmente antes de reportar (evita falsos positivos, ver la
    sección de falsos positivos de la metodología).
    """
    os.makedirs(outdir, exist_ok=True)
    severity = SEVERITY_BY_TYPE.get(tipo, "Informational")
    fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = os.path.join(outdir, f"reporte_{tipo}_{_slug(target_url, 30)}_{fecha}.md")

    lineas = [
        f"# Title: Posible {tipo.upper()} en {target_url}",
        "",
        f"**Severity:** {severity} (borrador -- ajustar tras validación manual y CVSS real)",
        "",
        "## Summary",
        f"Se detectaron {len(hallazgos_vulnerables)} respuesta(s) que difieren del baseline "
        f"de acceso denegado al manipular el/los parámetro(s) probados en `{target_url}`. "
        "Esto puede indicar control de acceso insuficiente. **Cada hallazgo debe validarse "
        "manualmente antes de reportar** -- este documento es un punto de partida, no un "
        "reporte final.",
        "",
        "## Steps to reproduce",
    ]
    for i, h in enumerate(hallazgos_vulnerables, 1):
        lineas.append(
            f"{i}. Probar `{h.get('id', h.get('payload'))}` -> "
            f"HTTP {h.get('status')} -- {h.get('desc')}"
        )
    lineas += [
        "",
        "## Impact",
        "_(completar tras confirmar qué datos/acciones de otro usuario quedan expuestos)_",
        "",
        "## Severity",
        f"{severity} -- CVSS a calcular según impacto de confidencialidad/integridad real confirmado.",
        "",
        "## Recommendation",
        "Verificar que cada endpoint valide que el recurso solicitado pertenece al usuario "
        "autenticado (control de acceso a nivel de objeto), no solo que exista una sesión válida.",
        "",
        "---",
        f"_Generado automáticamente por LETHAL el {fecha}. Evidencia cruda en `output/evidence/`._",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas))
    return path
