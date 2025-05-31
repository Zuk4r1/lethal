import os
import json
from urllib.parse import urlparse

from core.parser import (
    extraer_parametros_url,
    extraer_parametros_post,
    detectar_ids_enlace,
    encontrar_parametros_sensibles,
    es_json_valido
)

def cargar_capturas(ruta_directorio):
    """
    Carga todos los archivos JSON de un directorio (ZAP, Burp, etc.)
    """
    sesiones = []
    for archivo in os.listdir(ruta_directorio):
        if archivo.endswith(".json"):
            with open(os.path.join(ruta_directorio, archivo), 'r', encoding='utf-8') as f:
                try:
                    sesiones.append(json.load(f))
                except Exception as e:
                    print(f"[!] Error al cargar {archivo}: {e}")
    return sesiones

def analizar_sesiones(sesiones, debug=False):
    """
    Procesa las sesiones y extrae posibles objetivos sensibles para IDOR o CSRF.
    """
    rutas = {}

    # Lista ampliada de parámetros sensibles
    parametros_sensibles_extra = {
        "user", "usuario", "username", "email", "correo", "mail", "token", "csrf", "auth", "session", "clave", "contraseña", "password", "admin", "role", "rol", "apikey", "api_key", "secret"
    }

    def merge_dict_set(d, k, vals):
        if k not in d:
            d[k] = set()
        d[k].update(vals)

    for sesion in sesiones:
        for entrada in sesion.get("log", {}).get("entries", []):
            solicitud = entrada.get("request", {})
            respuesta = entrada.get("response", {})
            metodo = solicitud.get("method", "GET")
            url = solicitud.get("url", "")
            cuerpo = solicitud.get("postData", {}).get("text", "")
            contenido = respuesta.get("content", {}).get("text", "")
            cabeceras = {h["name"].lower(): h["value"] for h in solicitud.get("headers", [])}
            cookies = {c["name"]: c["value"] for c in solicitud.get("cookies", [])}

            ruta = urlparse(url).path

            if ruta not in rutas:
                rutas[ruta] = {
                    "parametros_get": {},
                    "parametros_post": {},
                    "ids_detectados": set(),
                    "sospechosos": set(),
                    "json_detectado": False,
                    "tokens_csrf": set(),
                    "cabeceras_interesantes": set(),
                    "metodos_http": set(),
                    "endpoint_peligroso": False,
                    "info_sensible_respuesta": set(),
                    "parametros_repetidos": set(),
                    "endpoint_upload": False,
                    "parametros_url": set(),
                    "parametros_reflejo": set(),
                    "parametros_array_objeto": set(),
                    "respuesta_grande": False,
                    "endpoint_backup": False,
                    "endpoint_debug": False,
                    "endpoint_versionado": False,
                    "parametros_comando": set(),
                    "parametros_bool": set(),
                    "parametros_num_secuencial": set(),
                    "cabeceras_inseguras": set(),
                    "leak_jwt": False,
                    "leak_session": False,
                    "leak_cookie": False,
                    "stacktrace": False,
                }

            rutas[ruta]["metodos_http"].add(metodo.upper())

            # Detección de endpoints peligrosos
            if any(x in ruta.lower() for x in ["delete", "remove", "update", "admin", "reset", "change", "edit"]):
                rutas[ruta]["endpoint_peligroso"] = True

            # Detección de cabeceras interesantes
            for h in cabeceras:
                if any(x in h for x in ["auth", "token", "csrf", "session", "cookie", "apikey", "api_key"]):
                    rutas[ruta]["cabeceras_interesantes"].add(h)

            # Detección de tokens CSRF en cookies
            for c in cookies:
                if "csrf" in c.lower() or "token" in c.lower():
                    rutas[ruta]["tokens_csrf"].add(c)

            # Detección de tokens CSRF en cabeceras
            for h in cabeceras:
                if "csrf" in h or "token" in h:
                    rutas[ruta]["tokens_csrf"].add(h)

            # Detección de parámetros GET
            if metodo.upper() in ("GET", "DELETE"):
                get_params = extraer_parametros_url(url)
                rutas[ruta]["parametros_get"].update(get_params)
                # IDs en URL y parámetros
                ids = set(detectar_ids_enlace(url))
                ids.update([v for v in get_params.values() if v.isdigit() or v.lower().endswith("id")])
                rutas[ruta]["ids_detectados"].update(ids)
                # Parámetros sensibles
                sospechosos = set(encontrar_parametros_sensibles(get_params))
                sospechosos.update({k for k in get_params if k.lower() in parametros_sensibles_extra})
                rutas[ruta]["sospechosos"].update(sospechosos)

            # Detección de parámetros POST/PUT
            elif metodo.upper() in ("POST", "PUT"):
                if es_json_valido(cuerpo):
                    rutas[ruta]["json_detectado"] = True
                    try:
                        post_params = json.loads(cuerpo)
                    except:
                        post_params = {}
                else:
                    post_params = extraer_parametros_post(cuerpo)

                rutas[ruta]["parametros_post"].update(post_params)
                # IDs en cuerpo y parámetros
                ids = set(detectar_ids_enlace(cuerpo))
                # IDs en JSON anidado
                def buscar_ids_json(obj):
                    encontrados = set()
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if "id" in k.lower() and (isinstance(v, str) and v.isdigit()):
                                encontrados.add(v)
                            elif isinstance(v, (dict, list)):
                                encontrados.update(buscar_ids_json(v))
                    elif isinstance(obj, list):
                        for item in obj:
                            encontrados.update(buscar_ids_json(item))
                    return encontrados
                ids.update(buscar_ids_json(post_params))
                rutas[ruta]["ids_detectados"].update(ids)
                # Parámetros sensibles
                sospechosos = set(encontrar_parametros_sensibles(post_params))
                sospechosos.update({k for k in post_params if k.lower() in parametros_sensibles_extra})
                rutas[ruta]["sospechosos"].update(sospechosos)

            # Detección de posibles tokens CSRF en respuestas HTML
            from core.parser import extraer_tokens_csrf
            try:
                tokens = extraer_tokens_csrf(contenido)
                if tokens:
                    rutas[ruta]["tokens_csrf"].update(tokens if isinstance(tokens, (list, set)) else [tokens])
            except Exception as e:
                if debug:
                    print(f"[DEBUG] Error extraer_tokens_csrf: {e}")

            # Detección de parámetros repetidos
            all_params = list(rutas[ruta]["parametros_get"].keys()) + list(rutas[ruta]["parametros_post"].keys())
            repetidos = set([p for p in all_params if all_params.count(p) > 1])
            rutas[ruta]["parametros_repetidos"].update(repetidos)

            # Detección de información sensible en respuesta
            patrones = [
                (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "email"),
                (r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}", "api_key"),
                (r"(?i)secret['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{8,}", "secret"),
                (r"(?i)token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9\-_=]{8,}", "token"),
                (r"(?i)pass(word)?['\"]?\s*[:=]\s*['\"]?.{6,}", "password"),
            ]
            import re
            for patron, tipo in patrones:
                if re.search(patron, contenido):
                    rutas[ruta]["info_sensible_respuesta"].add(tipo)

            # Detección de endpoints de subida de archivos
            if any(x in ruta.lower() for x in ["upload", "file", "archivo", "image", "media", "avatar"]):
                rutas[ruta]["endpoint_upload"] = True

            # Detección de posibles SSRF (parámetros con URLs)
            for k, v in list(rutas[ruta]["parametros_get"].items()) + list(rutas[ruta]["parametros_post"].items()):
                if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")):
                    rutas[ruta]["parametros_url"].add(k)

            # Detección de parámetros que aceptan arrays/objetos (para fuzzing avanzado)
            for k, v in list(rutas[ruta]["parametros_get"].items()) + list(rutas[ruta]["parametros_post"].items()):
                if isinstance(v, (list, dict)):
                    rutas[ruta]["parametros_array_objeto"].add(k)

            # Detección de posibles XSS (parámetros reflejados en respuesta)
            for k, v in list(rutas[ruta]["parametros_get"].items()) + list(rutas[ruta]["parametros_post"].items()):
                if isinstance(v, str) and v and v in contenido:
                    rutas[ruta]["parametros_reflejo"].add(k)

            # Detección de respuesta grande (posible fuga de datos)
            if isinstance(contenido, str) and len(contenido) > 100000:
                rutas[ruta]["respuesta_grande"] = True

            # Endpoints de backup, debug, test, staging, dev, old, temp
            if any(x in ruta.lower() for x in ["backup", "bak", "debug", "test", "staging", "dev", "old", "temp", "tmp", "~", ".swp", ".save"]):
                if any(x in ruta.lower() for x in ["backup", "bak", "old", "save"]):
                    rutas[ruta]["endpoint_backup"] = True
                if any(x in ruta.lower() for x in ["debug", "test", "staging", "dev", "tmp", ".swp"]):
                    rutas[ruta]["endpoint_debug"] = True

            # Endpoints versionados
            if any(x in ruta.lower() for x in ["/v1/", "/v2/", "/v3/", "/v4/", "/v5/", "/api/v", "/v0"]):
                rutas[ruta]["endpoint_versionado"] = True

            # Detección de parámetros que aceptan comandos/rutas (RCE/LFI)
            comando_keys = ["cmd", "exec", "command", "run", "shell", "path", "filepath", "file", "archivo", "dir", "directory"]
            for k, v in list(rutas[ruta]["parametros_get"].items()) + list(rutas[ruta]["parametros_post"].items()):
                if any(x in k.lower() for x in comando_keys):
                    rutas[ruta]["parametros_comando"].add(k)

            # Detección de parámetros booleanos
            for k, v in list(rutas[ruta]["parametros_get"].items()) + list(rutas[ruta]["parametros_post"].items()):
                if isinstance(v, str) and v.lower() in ("true", "false", "1", "0", "yes", "no"):
                    rutas[ruta]["parametros_bool"].add(k)

            # Detección de parámetros numéricos secuenciales
            for k, v in list(rutas[ruta]["parametros_get"].items()) + list(rutas[ruta]["parametros_post"].items()):
                if isinstance(v, str) and v.isdigit() and len(v) <= 6:
                    rutas[ruta]["parametros_num_secuencial"].add(k)

            # Detección de cabeceras inseguras en respuesta
            resp_headers = {h["name"].lower(): h["value"] for h in respuesta.get("headers", [])}
            inseguras = [
                ("access-control-allow-origin", "*"),
                ("x-frame-options", ""),
                ("x-content-type-options", ""),
                ("strict-transport-security", ""),
                ("content-security-policy", ""),
            ]
            for h, val in inseguras:
                if h in resp_headers and (resp_headers[h] == val or resp_headers[h] == ""):
                    rutas[ruta]["cabeceras_inseguras"].add(h)

            # Detección de leaks de JWT/session/cookie en respuesta
            if "eyJ" in contenido and "." in contenido:  # JWT típico
                rutas[ruta]["leak_jwt"] = True
            if "session" in contenido.lower():
                rutas[ruta]["leak_session"] = True
            if "set-cookie" in contenido.lower():
                rutas[ruta]["leak_cookie"] = True

            # Detección de stacktrace o error backend
            errores = ["exception", "traceback", "fatal error", "stacktrace", "at ", "sql syntax", "warning", "not defined", "undefined", "cannot read property", "nullpointer", "segmentation fault"]
            if any(e in contenido.lower() for e in errores):
                rutas[ruta]["stacktrace"] = True

    # Convertir sets a listas para impresión
    for ruta in rutas:
        rutas[ruta]["ids_detectados"] = list(rutas[ruta]["ids_detectados"])
        rutas[ruta]["sospechosos"] = list(rutas[ruta]["sospechosos"])
        rutas[ruta]["tokens_csrf"] = list(rutas[ruta]["tokens_csrf"])
        rutas[ruta]["cabeceras_interesantes"] = list(rutas[ruta]["cabeceras_interesantes"])
        rutas[ruta]["parametros_repetidos"] = list(rutas[ruta]["parametros_repetidos"])
        rutas[ruta]["info_sensible_respuesta"] = list(rutas[ruta]["info_sensible_respuesta"])
        rutas[ruta]["parametros_url"] = list(rutas[ruta]["parametros_url"])
        rutas[ruta]["parametros_reflejo"] = list(rutas[ruta]["parametros_reflejo"])
        rutas[ruta]["parametros_array_objeto"] = list(rutas[ruta]["parametros_array_objeto"])
        rutas[ruta]["parametros_comando"] = list(rutas[ruta]["parametros_comando"])
        rutas[ruta]["parametros_bool"] = list(rutas[ruta]["parametros_bool"])
        rutas[ruta]["parametros_num_secuencial"] = list(rutas[ruta]["parametros_num_secuencial"])
        rutas[ruta]["cabeceras_inseguras"] = list(rutas[ruta]["cabeceras_inseguras"])

    return rutas

def imprimir_resumen(rutas):
    """
    Imprime un resumen de rutas sensibles encontradas.
    """
    print("\n[+] Resumen de rutas sospechosas:")
    for ruta, datos in rutas.items():
        print(f"\n==> {ruta}")
        print("  [*] Métodos HTTP:", list(datos.get("metodos_http", [])))
        if datos.get("endpoint_peligroso"):
            print("  [!] Endpoint potencialmente peligroso (delete/update/admin/etc)")
        if datos.get("endpoint_upload"):
            print("  [!] Endpoint de subida de archivos detectado")
        if datos.get("endpoint_backup"):
            print("  [!] Endpoint de backup/temp/old detectado")
        if datos.get("endpoint_debug"):
            print("  [!] Endpoint de debug/test/dev detectado")
        if datos.get("endpoint_versionado"):
            print("  [*] Endpoint versionado detectado")
        if datos["parametros_get"]:
            print("  [GET] Parámetros:", list(datos["parametros_get"].keys()))
        if datos["parametros_post"]:
            print("  [POST] Parámetros:", list(datos["parametros_post"].keys()))
        if datos["parametros_repetidos"]:
            print("  [!] Parámetros repetidos:", list(datos["parametros_repetidos"]))
        if datos["ids_detectados"]:
            print("  [!] Posibles ID detectados:", datos["ids_detectados"])
        if datos["sospechosos"]:
            print("  [!] Parámetros sensibles:", datos["sospechosos"])
        if datos["json_detectado"]:
            print("  [*] Datos enviados como JSON.")
        if datos["tokens_csrf"]:
            print("  [*] Tokens CSRF detectados:", datos["tokens_csrf"])
        if datos.get("cabeceras_interesantes"):
            print("  [*] Cabeceras interesantes:", datos["cabeceras_interesantes"])
        if datos.get("cabeceras_inseguras"):
            print("  [!] Cabeceras inseguras en respuesta:", datos["cabeceras_inseguras"])
        if datos.get("info_sensible_respuesta"):
            print("  [!] Información sensible en respuesta:", list(datos["info_sensible_respuesta"]))
        if datos.get("parametros_url"):
            print("  [!] Parámetros que parecen URL (posible SSRF):", datos["parametros_url"])
        if datos.get("parametros_reflejo"):
            print("  [!] Parámetros reflejados en respuesta (posible XSS):", datos["parametros_reflejo"])
        if datos.get("parametros_array_objeto"):
            print("  [*] Parámetros que aceptan arrays/objetos:", datos["parametros_array_objeto"])
        if datos.get("parametros_comando"):
            print("  [!] Parámetros de comando/ruta (posible RCE/LFI):", datos["parametros_comando"])
        if datos.get("parametros_bool"):
            print("  [*] Parámetros booleanos:", datos["parametros_bool"])
        if datos.get("parametros_num_secuencial"):
            print("  [*] Parámetros numéricos secuenciales:", datos["parametros_num_secuencial"])
        if datos.get("leak_jwt"):
            print("  [!] Posible JWT expuesto en respuesta")
        if datos.get("leak_session"):
            print("  [!] Posible session expuesta en respuesta")
        if datos.get("leak_cookie"):
            print("  [!] Posible set-cookie expuesto en respuesta")
        if datos.get("respuesta_grande"):
            print("  [!] Respuesta muy grande, posible fuga de datos")
        if datos.get("stacktrace"):
            print("  [!] Stacktrace o error de backend detectado")
        # Letalidad máxima: advertencias adicionales
        if any(x in ruta.lower() for x in [
            "admin", "root", "superuser", "system", "internal", "private", "confidential", "restricted", "secreto", "forbidden", "hidden", "vault", "secure", "master", "god", "owner"
        ]):
            print("  [!!!] Ruta crítica: acceso administrativo, interno o restringido detectado")
        if any(x in ruta.lower() for x in [
            ".git", ".svn", ".env", ".bak", ".old", ".zip", ".tar", ".gz", ".db", ".sqlite", ".log", ".pem", ".crt", ".key", ".aws", ".azure", ".gcp", ".psql", ".mysql", ".backup", ".bkp", ".rar", ".7z", ".pfx", ".ovpn", ".ppk", ".ssh", ".docker", ".npmrc", ".htpasswd", ".htaccess"
        ]):
            print("  [!!!] Posible fuga de código fuente, credenciales, backups o archivos sensibles expuestos")
        if datos.get("parametros_get") and any(
            any(s in k.lower() for s in [
                "password", "token", "secret", "key", "apikey", "api_key", "auth", "session", "jwt", "credential", "clave", "contraseña", "passwd", "access", "refresh", "bearer"
            ]) for k in datos["parametros_get"]
        ):
            print("  [!!!] Parámetros GET con datos ultra sensibles detectados")
        if datos.get("parametros_post") and any(
            any(s in k.lower() for s in [
                "password", "token", "secret", "key", "apikey", "api_key", "auth", "session", "jwt", "credential", "clave", "contraseña", "passwd", "access", "refresh", "bearer"
            ]) for k in datos["parametros_post"]
        ):
            print("  [!!!] Parámetros POST con datos ultra sensibles detectados")
        # Ataque avanzado: advertencia si endpoint parece permitir métodos peligrosos
        metodos_peligrosos = {"PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE", "PROPFIND", "COPY", "MOVE"}
        if set(datos.get("metodos_http", [])) & metodos_peligrosos:
            print("  [!!!] Métodos HTTP peligrosos habilitados:", list(set(datos.get("metodos_http", [])) & metodos_peligrosos))
        # Ataque avanzado: advertencia si hay parámetros con nombres de bypass típicos
        bypass_keywords = [
            "bypass", "override", "force", "admin", "debug", "test", "dev", "disable", "enable", "allow", "unlocked", "unlock", "elevate", "super", "god", "root", "hacker", "hack"
        ]
        if any(any(b in k.lower() for b in bypass_keywords) for k in list(datos.get("parametros_get", {}).keys()) + list(datos.get("parametros_post", {}).keys())):
            print("  [!!!] Parámetros de bypass/lógica privilegiada detectados")
        # Ataque avanzado: advertencia si hay parámetros con valores sospechosos de inyección
        inyeccion_keywords = [
            "'", "\"", ";", "--", "/*", "*/", "`", "$(", "${", "<", ">", "|", "&", "\\", "||", "&&", "%00", "%27", "%22", "%3C", "%3E", "%3B", "%24", "%7C", "%26", "%60"
        ]
        if any(any(x in str(v) for x in inyeccion_keywords) for v in list(datos.get("parametros_get", {}).values()) + list(datos.get("parametros_post", {}).values())):
            print("  [!!!] Valores de parámetros con posible inyección detectada")
        # Ataque avanzado: advertencia si hay parámetros con nombres de ruta, archivo o sistema
        ruta_keywords = [
            "path", "filepath", "file", "archivo", "dir", "directory", "folder", "ruta", "location", "url", "link", "redirect", "next", "dest", "destino", "target", "source", "src"
        ]
        if any(any(rk in k.lower() for rk in ruta_keywords) for k in list(datos.get("parametros_get", {}).keys()) + list(datos.get("parametros_post", {}).keys())):
            print("  [!!!] Parámetros de ruta/archivo/sistema detectados (posible LFI/RFI/SSRF/Open Redirect)")
        # Ataque avanzado: advertencia si hay parámetros con nombres de usuario o email
        usuario_keywords = [
            "user", "usuario", "username", "mail", "correo", "email", "login", "account", "cuenta", "profile", "perfil", "member", "miembro"
        ]
        if any(any(u in k.lower() for u in usuario_keywords) for k in list(datos.get("parametros_get", {}).keys()) + list(datos.get("parametros_post", {}).keys())):
            print("  [*] Parámetros de usuario/email detectados (posible enumeración o acceso no autorizado)")
        # Ataque avanzado: advertencia si la ruta contiene palabras de staging, QA, preprod, etc.
        entorno_keywords = [
            "staging", "qa", "preprod", "pre-production", "test", "dev", "sandbox", "demo", "beta", "alpha", "trial"
        ]
        if any(x in ruta.lower() for x in entorno_keywords):
            print("  [*] Ruta de entorno no productivo detectada (posible entorno inseguro o expuesto)")
