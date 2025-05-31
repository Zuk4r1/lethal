from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style
import re
import base64
import hashlib

# Patrones ampliados para IDOR
PATRONES_IDOR = [
    'id', 'user', 'userid', 'account', 'accountid', 'uid', 'profile', 'profileid', 'order', 'orderid',
    'doc', 'docid', 'invoice', 'invoiceid', 'client', 'clientid', 'contact', 'contactid', 'member',
    'memberid', 'number', 'num', 'record', 'recordid', 'reference', 'ref', 'customer', 'customerid',
    'emp', 'employee', 'employeeid', 'admin', 'adminid', 'session', 'sessionid', 'token', 'object',
    'objectid', 'item', 'itemid', 'resource', 'resourceid', 'file', 'fileid', 'group', 'groupid',
    'team', 'teamid', 'project', 'projectid', 'folder', 'folderid', 'cart', 'cartid', 'list', 'listid',
    'msg', 'message', 'messageid', 'noti', 'notification', 'notificationid', 'blog', 'blogid', 'post',
    'postid', 'comment', 'commentid', 'photo', 'photoid', 'image', 'imageid', 'album', 'albumid',
    'video', 'videoid', 'media', 'mediaid', 'event', 'eventid', 'task', 'taskid', 'case', 'caseid',
    'lead', 'leadid', 'ticket', 'ticketid', 'request', 'requestid', 'submission', 'submissionid',
    'application', 'applicationid', 'student', 'studentid', 'teacher', 'teacherid', 'course', 'courseid',
    'class', 'classid', 'school', 'schoolid', 'org', 'organization', 'organizationid', 'dept', 'department',
    'departmentid', 'branch', 'branchid', 'location', 'locationid', 'address', 'addressid', 'phone',
    'phoneid', 'mobile', 'mobileid', 'device', 'deviceid', 'hardware', 'hardwareid', 'software', 'softwareid',
    'license', 'licenseid', 'serial', 'serialid', 'pin', 'pincode', 'ssn', 'passport', 'passportid',
    'driver', 'driverid', 'vehicle', 'vehicleid', 'plate', 'plateid', 'shipment', 'shipmentid', 'tracking',
    'trackingid', 'payment', 'paymentid', 'payid', 'transaction', 'transactionid', 'bank', 'bankid',
    'card', 'cardid', 'accountnumber', 'iban', 'swift', 'bic', 'tax', 'taxid', 'vat', 'vatid', 'ssn',
    'social', 'socialid', 'insurance', 'insuranceid', 'policy', 'policyid', 'claim', 'claimid', 'vote',
    'voteid', 'poll', 'pollid', 'survey', 'surveyid', 'answer', 'answerid', 'result', 'resultid', 'score',
    'scoreid', 'grade', 'gradeid', 'mark', 'markid', 'rank', 'rankid', 'level', 'levelid', 'stage',
    'stageid', 'step', 'stepid', 'phase', 'phaseid', 'round', 'roundid', 'match', 'matchid', 'game',
    'gameid', 'player', 'playerid', 'team', 'teamid', 'club', 'clubid', 'league', 'leagueid', 'season',
    'seasonid', 'tournament', 'tournamentid', 'competition', 'competitionid', 'award', 'awardid', 'medal',
    'medalid', 'badge', 'badgeid', 'certificate', 'certificateid', 'document', 'documentid', 'file',
    'fileid', 'folder', 'folderid', 'archive', 'archiveid', 'log', 'logid', 'entry', 'entryid', 'row',
    'rowid', 'col', 'column', 'columnid', 'cell', 'cellid', 'sheet', 'sheetid', 'tab', 'tabid', 'section',
    'sectionid', 'part', 'partid', 'segment', 'segmentid', 'block', 'blockid', 'node', 'nodeid', 'edge',
    'edgeid', 'vertex', 'vertexid', 'point', 'pointid', 'zone', 'zoneid', 'area', 'areaid', 'region',
    'regionid', 'country', 'countryid', 'state', 'stateid', 'province', 'provinceid', 'city', 'cityid',
    'town', 'townid', 'village', 'villageid', 'district', 'districtid', 'street', 'streetid', 'road',
    'roadid', 'lane', 'laneid', 'route', 'routeid', 'path', 'pathid', 'way', 'wayid', 'track', 'trackid',
    'trail', 'trailid', 'line', 'lineid', 'station', 'stationid', 'stop', 'stopid', 'terminal', 'terminalid',
    'gate', 'gateid', 'port', 'portid', 'dock', 'dockid', 'pier', 'pierid', 'bridge', 'bridgeid', 'tunnel',
    'tunnelid', 'crossing', 'crossingid', 'checkpoint', 'checkpointid', 'border', 'borderid', 'customs',
    'customsid', 'immigration', 'immigrationid', 'visa', 'visaid', 'permit', 'permitid', 'license',
    'licenseid', 'certificate', 'certificateid', 'approval', 'approvalid', 'clearance', 'clearanceid'
]

RE_IDOR = re.compile(
    r'(' + '|'.join(PATRONES_IDOR) + r')(_?id|Id|ID)?$', re.IGNORECASE
)

def es_base64(s):
    # Mejorada: ignora padding y caracteres no válidos
    try:
        s_clean = s.strip().replace('-', '+').replace('_', '/')
        if len(s_clean) % 4 == 0 and re.fullmatch(r'[A-Za-z0-9+/=]+', s_clean):
            base64.b64decode(s_clean, validate=True)
            return True
    except Exception:
        return False
    return False

def es_hash(valor):
    # Mejorada: detecta hashes hex y base64
    hashes = [
        r'^[a-f0-9]{32}$',      # md5
        r'^[a-f0-9]{40}$',      # sha1
        r'^[a-f0-9]{64}$',      # sha256
        r'^[a-f0-9]{128}$',     # sha512
    ]
    if any(re.fullmatch(h, valor.lower()) for h in hashes):
        return True
    # Hash en base64 (típico sha256)
    if es_base64(valor) and len(valor) in (44, 24):
        return True
    return False

def es_lista_ids(valor):
    # Mejorada: detecta listas mixtas de ids, hex, uuid
    sep = [',', '|', ';']
    for s in sep:
        partes = valor.split(s)
        if len(partes) > 1 and all(
            x.strip().isdigit() or
            re.fullmatch(r'[a-fA-F0-9]{8,}', x.strip()) or
            re.fullmatch(r'[a-f0-9\-]{36}', x.strip())
            for x in partes
        ):
            return True
    return False

def analizar_param(param, valor):
    # Potente: detecta ids, hex, uuid, base64, hash, listas, patrones de ofuscación y valores sospechosos
    if (
        RE_IDOR.search(param)
        and (
            valor.isdigit() or
            re.fullmatch(r'[a-fA-F0-9]{8,}', valor) or
            re.fullmatch(r'[a-f0-9\-]{36}', valor) or
            es_base64(valor) or
            es_hash(valor) or
            es_lista_ids(valor)
        )
    ):
        return True
    # Detecta parámetros sospechosos por nombre y longitud
    if len(valor) > 12 and RE_IDOR.search(param):
        return True
    # Detecta parámetros con nombre ofuscado pero valor sospechoso
    if re.search(r'(id|uid|user|token|ref|num|account)', param, re.IGNORECASE) and (
        valor.isdigit() or es_hash(valor) or es_base64(valor)
    ):
        return True
    return False

def detectar_idor(url, silent=False):
    hallazgos = []
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    fragment = parse_qs(parsed.fragment)

    # Query params
    for param, valores in query.items():
        for valor in valores:
            if analizar_param(param, valor):
                hallazgos.append((param, valor))
                if not silent:
                    print(f"{Fore.YELLOW}[!] Posible parámetro IDOR: {param}={valor}{Style.RESET_ALL}")

    # Fragment params (#)
    for param, valores in fragment.items():
        for valor in valores:
            if analizar_param(param, valor):
                hallazgos.append((f"fragment:{param}", valor))
                if not silent:
                    print(f"{Fore.YELLOW}[!] Posible parámetro IDOR en fragmento: {param}={valor}{Style.RESET_ALL}")

    # Path
    path_parts = parsed.path.strip('/').split('/')
    for i, part in enumerate(path_parts):
        if (
            part.isdigit() or
            re.fullmatch(r'[a-fA-F0-9]{8,}', part) or
            re.fullmatch(r'[a-f0-9\-]{36}', part) or
            es_base64(part) or
            es_hash(part)
        ):
            if i > 0 and RE_IDOR.search(path_parts[i-1]):
                hallazgos.append((f"path:{path_parts[i-1]}", part))
                if not silent:
                    print(f"{Fore.YELLOW}[!] Posible IDOR en path: .../{path_parts[i-1]}/{part}{Style.RESET_ALL}")

    # Detección de parámetros duplicados (típico en IDOR)
    if len(set(hallazgos)) != len(hallazgos) and not silent:
        print(f"{Fore.LIGHTYELLOW_EX}[!] Hay parámetros repetidos, posible manipulación de IDOR.{Style.RESET_ALL}")

    if not hallazgos and not silent:
        print(f"{Fore.BLUE}[-] No se detectaron parámetros sospechosos para IDOR.{Style.RESET_ALL}")
    elif hallazgos and not silent:
        print(f"{Fore.GREEN}[+] SUGERENCIA: Prueba cambiar los valores detectados por otros IDs, hashes, o combinaciones para verificar acceso indebido. Automatiza con secuencias, fuzzing, o herramientas como ffuf/burp.{Style.RESET_ALL}")

    return hallazgos

# CSRF avanzado
TOKENS_CSRF = [
    'x-csrf-token', 'x-xsrf-token', 'csrf-token', 'x-request-token', 'csrfmiddlewaretoken',
    'authenticity_token', 'csrf', 'xsrf', 'requesttoken', 'anti-csrf', 'anti_xsrf', 'csrf_token',
    'xsrf_token', 'csrfmiddleware', 'csrftoken', 'xsrfmiddlewaretoken', 'csrf_token_name',
    'csrf_token_value', 'csrf_token_key', 'csrf_token_field', 'csrf_token_header', 'csrf_token_cookie',
    'csrf_token_param', 'csrf_token_query', 'csrf_token_form', 'csrf_token_body', 'csrf_token_url',
    'csrf_token_session', 'csrf_token_storage', 'csrf_token_local', 'csrf_token_global', 'csrf_token_random',
    'csrf_token_dynamic', 'csrf_token_static', 'csrf_token_custom', 'csrf_token_secret', 'csrf_token_salt',
    'csrf_token_hash', 'csrf_token_digest', 'csrf_token_signature', 'csrf_token_nonce', 'csrf_token_crumb',
    'csrf_token_protect', 'csrf_token_secure', 'csrf_token_auth', 'csrf_token_verify', 'csrf_token_check',
    'csrf_token_validate', 'csrf_token_confirm', 'csrf_token_assert', 'csrf_token_guard', 'csrf_token_shield',
    'csrf_token_defend', 'csrf_token_block', 'csrf_token_stop', 'csrf_token_prevent', 'csrf_token_avoid',
    'csrf_token_bypass', 'csrf_token_escape', 'csrf_token_filter', 'csrf_token_intercept', 'csrf_token_monitor',
    'csrf_token_observe', 'csrf_token_watch', 'csrf_token_track', 'csrf_token_trace', 'csrf_token_log',
    'csrf_token_report', 'csrf_token_alert', 'csrf_token_warn', 'csrf_token_notice', 'csrf_token_info',
    'csrf_token_debug', 'csrf_token_test', 'csrf_token_trial', 'csrf_token_demo', 'csrf_token_sample',
    'csrf_token_example', 'csrf_token_case', 'csrf_token_scenario', 'csrf_token_event', 'csrf_token_action',
    'csrf_token_activity', 'csrf_token_task', 'csrf_token_job', 'csrf_token_work', 'csrf_token_process',
    'csrf_token_operation', 'csrf_token_function', 'csrf_token_method', 'csrf_token_procedure', 'csrf_token_routine',
    'csrf_token_script', 'csrf_token_program', 'csrf_token_app', 'csrf_token_application', 'csrf_token_service',
    'csrf_token_api', 'csrf_token_endpoint', 'csrf_token_url', 'csrf_token_path', 'csrf_token_route',
    'csrf_token_page', 'csrf_token_view', 'csrf_token_form', 'csrf_token_input', 'csrf_token_field',
    'csrf_token_param', 'csrf_token_query', 'csrf_token_body', 'csrf_token_header', 'csrf_token_cookie',
    'csrf_token_session', 'csrf_token_storage', 'csrf_token_local', 'csrf_token_global', 'csrf_token_random',
    'csrf_token_dynamic', 'csrf_token_static', 'csrf_token_custom', 'csrf_token_secret', 'csrf_token_salt',
    'csrf_token_hash', 'csrf_token_digest', 'csrf_token_signature', 'csrf_token_nonce', 'csrf_token_crumb',
    'csrf_token_protect', 'csrf_token_secure', 'csrf_token_auth', 'csrf_token_verify', 'csrf_token_check',
    'csrf_token_validate', 'csrf_token_confirm', 'csrf_token_assert', 'csrf_token_guard', 'csrf_token_shield',
    'csrf_token_defend', 'csrf_token_block', 'csrf_token_stop', 'csrf_token_prevent', 'csrf_token_avoid',
    'csrf_token_bypass', 'csrf_token_escape', 'csrf_token_filter', 'csrf_token_intercept', 'csrf_token_monitor',
    'csrf_token_observe', 'csrf_token_watch', 'csrf_token_track', 'csrf_token_trace', 'csrf_token_log',
    'csrf_token_report', 'csrf_token_alert', 'csrf_token_warn', 'csrf_token_notice', 'csrf_token_info',
    'csrf_token_debug', 'csrf_token_test', 'csrf_token_trial', 'csrf_token_demo', 'csrf_token_sample',
    'csrf_token_example', 'csrf_token_case', 'csrf_token_scenario', 'csrf_token_event', 'csrf_token_action',
    'csrf_token_activity', 'csrf_token_task', 'csrf_token_job', 'csrf_token_work', 'csrf_token_process',
    'csrf_token_operation', 'csrf_token_function', 'csrf_token_method', 'csrf_token_procedure', 'csrf_token_routine',
    'crumb', 'nonce', 'anti-csrf', 'anti_xsrf', 'x-csrf', 'x-xsrf', 'csrfmiddlewaretoken', 'csrftoken'
]

def token_en_body(body):
    if not body:
        return False
    # Mejorada: busca tokens en formato JSON y urlencoded
    if isinstance(body, dict):
        body_str = "&".join(f"{k}={v}" for k, v in body.items())
    else:
        body_str = str(body)
    return any(t in body_str.lower() for t in TOKENS_CSRF)

def token_en_url(url):
    if not url:
        return False
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    return any(t in query for t in TOKENS_CSRF)

def token_en_cookie(headers):
    cookies = headers.get('cookie', '') or headers.get('Cookie', '')
    return any(t in cookies.lower() for t in TOKENS_CSRF)

def token_ofuscado(headers):
    # Mejorada: detecta tokens CSRF personalizados y variantes
    for k in headers:
        if re.search(r'(csrf|xsrf|token|sec|anti|protect|crumb|nonce)', k, re.IGNORECASE):
            return True
    return False

def detectar_csrf(method, headers, body=None, url=None, silent=False):
    method = method.upper()
    cabeceras = {k.lower(): v for k, v in headers.items()}
    sospechoso = False

    tiene_token_header = any(k in cabeceras for k in TOKENS_CSRF)
    tiene_token_body = token_en_body(body)
    tiene_token_url = token_en_url(url)
    tiene_token_cookie = token_en_cookie(headers)
    tiene_cookie = 'cookie' in cabeceras or 'Cookie' in headers

    # Detección de autenticación (Bearer, JWT, Basic, etc.)
    tiene_auth = any(k in cabeceras for k in ['authorization', 'auth', 'x-api-key', 'apikey', 'api-key'])
    auth_val = cabeceras.get('authorization', '').lower()
    es_jwt = 'bearer' in auth_val or re.match(r'^[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$', auth_val)

    # Métodos y rutas sensibles
    metodos_csrf = ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    es_cors = 'origin' in cabeceras or 'referer' in cabeceras
    ruta_sensible = False
    if url:
        parsed = urlparse(url)
        ruta_sensible = any(x in parsed.path.lower() for x in [
            'delete', 'update', 'edit', 'change', 'remove', 'transfer', 'admin', 'config', 'password', 'reset', 'email', 'bank', 'money', 'account'
        ])

    # Detección de SameSite en cookies
    same_site = False
    cookies = headers.get('cookie', '') or headers.get('Cookie', '')
    if 'samesite' in cookies.lower():
        same_site = True

    if method in metodos_csrf:
        if not (tiene_token_header or tiene_token_body or tiene_token_url or tiene_token_cookie or token_ofuscado(cabeceras)) and tiene_cookie:
            sospechoso = True
            if not silent:
                print(f"{Fore.RED}[!!] Endpoint potencialmente vulnerable a CSRF (método {method}, sin token en header/body/url/cookie y con cookies).{Style.RESET_ALL}")
                if es_cors:
                    print(f"{Fore.MAGENTA}[!] El endpoint acepta CORS, lo que puede aumentar el riesgo de CSRF.{Style.RESET_ALL}")
                if ruta_sensible:
                    print(f"{Fore.LIGHTRED_EX}[!] La ruta parece sensible: {parsed.path}{Style.RESET_ALL}")
                if not same_site:
                    print(f"{Fore.YELLOW}[!] Las cookies no tienen atributo SameSite, lo que facilita ataques CSRF.{Style.RESET_ALL}")
                if tiene_auth:
                    print(f"{Fore.CYAN}[!] El endpoint requiere autenticación (ej: Authorization, API Key), pero esto no protege contra CSRF si depende de cookies.{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] SUGERENCIA: Prueba enviar la petición desde otro origen, sin token, y observa si la acción se ejecuta. Usa Burp, Postman, HTML malicioso, y prueba con métodos y cabeceras atípicas. Automatiza con herramientas como CSRF-Tester.{Style.RESET_ALL}")
        elif not silent:
            print(f"{Fore.BLUE}[-] Endpoint protegido contra CSRF (token detectado en header/body/url/cookie, token ofuscado, o sin cookies).{Style.RESET_ALL}")
            if same_site:
                print(f"{Fore.GREEN}[+] Las cookies tienen SameSite, lo que mitiga CSRF.{Style.RESET_ALL}")
            if es_jwt:
                print(f"{Fore.GREEN}[+] El endpoint usa JWT/Bearer, lo que reduce el riesgo de CSRF si no depende de cookies.{Style.RESET_ALL}")
            if tiene_token_header or tiene_token_body or tiene_token_url or tiene_token_cookie or token_ofuscado(cabeceras):
                print(f"{Fore.GREEN}[+] Se detectó algún tipo de token anti-CSRF, revisa si es realmente aleatorio y cambia en cada petición.{Style.RESET_ALL}")
    else:
        if not silent:
            print(f"{Fore.BLUE}[-] Método {method} no se considera típicamente vulnerable a CSRF.{Style.RESET_ALL}")

    return sospechoso
