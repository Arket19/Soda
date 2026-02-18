"""
    Este módulo define todas las constantes y configuraciones globales que utilizan
    los demás módulos del proyecto. 
"""

from typing import Dict, List, Any

###################### CONFIGURACIÓN DE RED ######################

#Timeout por defecto para peticiones HTTP (en segundos)
TIMEOUT_POR_DEFECTO: float = 5

#Máximo número de reintentos para peticiones fallidas
MAX_REINTENTOS: int = 3

#Delay base entre reintentos (en segundos) 
BASE_BACKOFF: float = 2.0
    #Tabla de tiempos de espera según valor de la base (hasta 5 intentos)
    #BASE_BACKOFF = 1 -> 1s, 2s, 4s, 8s, 16s
    #BASE_BACKOFF = 2 -> 2s, 4s, 8s, 16s, 32s
    #BASE_BACKOFF = 3 -> 3s, 6s, 12s, 24s, 48s
    #BASE_BACKOFF = 4 -> 4s, 8s, 16s, 32s, 64s
    #BASE_BACKOFF = 5 -> 5s, 10s, 20s, 40s, 80s

#Número máximo de conexiones simultáneas con el objetivo
MAX_CONEXIONES: int = 20



###################### USER AGENTS ######################

#User-Agent por defecto para las peticiones
USER_AGENT_POR_DEFECTO: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

#Lista de User-Agents para rotación (anti-fingerprinting)
LISTA_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]



###################### CRAWLER (MAP) ######################

#Delay base entre peticiones del crawler (en segundos)
DELAY_BASE_CRAWLER: float = 1.0

#Rango min/max de variación aleatoria que se suma al delay base
RANGO_JITTER_CRAWLER: tuple = (0.3, 1.0)

#Número máximo de reintentos del crawler por petición fallida
MAX_REINTENTOS_CRAWLER: int = 3

#Timeout del crawler por petición (en segundos)
TIMEOUT_CRAWLER: int = 5

#Número máximo de URLs que el crawler recopilará antes de detenerse
MAX_URLS_CRAWLER: int = 25000

#Número máximo de URLs hijas de un mismo directorio en el discoverer.
MAX_URLS_DIRECTORIO: int = 30

#Navegadores disponibles en curl_cffi para suplantación
SUPLANTACIONES_NAVEGADOR: List[str] = [
    'chrome120',
    'chrome119',
    'chrome110',
    'chrome107',
    'safari17_0',
    'safari15_5',
    'edge99'
]

#Extensiones de archivos estáticos a ignorar durante el crawleo
EXTENSIONES_ESTATICAS = (
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp',
    '.css', '.js',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.tar', '.gz', '.7z',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.webm', '.ogg',
    '.xml', '.rss', '.atom', '.webmanifest', '.manifest',
)



###################### FUZZER (ACTIVE) ######################

#Códigos de respuesta HTTP que indican recursos encontrados
CODIGOS_EXITO: List[int] = [200, 201, 204, 301, 302, 307, 308, 401, 403]

#Extensiones de archivo comunes para fuzzing
EXTENSIONES_COMUNES: List[str] = [
    ".php",      
    ".asp",      
    ".aspx",     
    ".jsp",      
    ".html",     
    ".js",       
    ".css",      
    ".json",     
    ".xml",      
    ".txt",      
    ".bak",      
    ".old",      
    ".zip",      
    ".tar.gz",   
]



###################### WAF DETECT (ACTIVE) ######################

#Firmas de WAFs conocidos para detección pasiva por headers/cookies
FIRMAS_WAF: Dict[str, Dict[str, Any]] = {
    "Cloudflare": {
        "headers": {"cf-ray": r".*", "server": r"cloudflare"},
        "cookies": ["__cfduid", "cf_clearance"],
    },
    "AWS WAF": {
        "headers": {"x-amzn-requestid": r".*"},
    },
    "Akamai": {
        "headers": {"x-akamai-session": r".*", "server": r"akamaighost"},
    },
    "Imperva": {
        "headers": {"x-iinfo": r".*"},
        "cookies": ["incap_ses"],
    },
    "ModSecurity": {
        "headers": {"server": r"mod_security"},
    },
    "Sucuri": {
        "headers": {"x-sucuri-id": r".*"},
    },
    "F5 BIG-IP": {
        "headers": {"server": r"bigip"},
        "cookies": ["TS", "F5"],
    },
    "PRISMA": {
        "headers": {"x-prisma-event-id": r".*"}
    },
}

#Payloads de prueba para detección activa de WAF
PAYLOADS_PRUEBA: List[Dict[str, str]] = [
    {"name": "SQLi", "param": "id", "value": "1' OR '1'='1"},
    {"name": "XSS", "param": "q", "value": "<script>alert(1)</script>"},
]



###################### HEADERS ANALYZER (PASSIVE) ######################

#URLs del OWASP Secure Headers Project para descargar recomendaciones
URL_OWASP_HEADERS_ADD: str = "https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_add.json"
URL_OWASP_HEADERS_REMOVE: str = "https://raw.githubusercontent.com/OWASP/www-project-secure-headers/master/ci/headers_remove.json"

#Cabeceras recomendadas por OWASP (fallback si no hay conexión)
FALLBACK_HEADERS_RECOMENDADOS: Dict[str, str] = {
    "Cache-Control": "no-store, max-age=0",
    "Clear-Site-Data": '"cache","cookies","storage"',
    "Content-Security-Policy": "default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "accelerometer=(), autoplay=(), camera=(), cross-origin-isolated=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=(), clipboard-read=(), clipboard-write=(), gamepad=(), hid=(), idle-detection=(), interest-cohort=(), serial=(), unload=()",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-DNS-Prefetch-Control": "off",
    "X-Frame-Options": "deny",
    "X-Permitted-Cross-Domain-Policies": "none",
}

#Cabeceras que OWASP recomienda eliminar (fallback si no hay conexión)
FALLBACK_HEADERS_QUITAR: List[str] = [
    "$wsep", "Host-Header", "K-Proxy-Request", "Liferay-Portal",
    "OracleCommerceCloud-Version", "Pega-Host", "Powered-By", "Product",
    "Server", "SourceMap", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Atmosphere-error", "X-Atmosphere-first-request", "X-Atmosphere-tracking-id",
    "X-B3-ParentSpanId", "X-B3-Sampled", "X-B3-SpanId", "X-B3-TraceId",
    "X-BEServer", "X-Backside-Transport", "X-CF-Powered-By", "X-CMS",
    "X-CalculatedBEobjetivo", "X-Cocoon-Version", "X-Content-Encoded-By",
    "X-DiagInfo", "X-Envoy-Attempt-Count", "X-Envoy-External-Address",
    "X-Envoy-Internal", "X-Envoy-Original-Dst-Host", "X-Envoy-Upstream-Service-Time",
    "X-FEServer", "X-Framework", "X-Generated-By", "X-Generator",
    "X-Jitsi-Release", "X-Joomla-Version", "X-Kubernetes-PF-FlowSchema-UI",
    "X-Kubernetes-PF-PriorityLevel-UID", "X-LiteSpeed-Cache", "X-LiteSpeed-Purge",
    "X-LiteSpeed-Tag", "X-LiteSpeed-Vary", "X-Litespeed-Cache-Control",
    "X-Mod-Pagespeed", "X-Nextjs-Cache", "X-Nextjs-Matched-Path",
    "X-Nextjs-Page", "X-Nextjs-Redirect", "X-OWA-Version", "X-Old-Content-Length",
    "X-OneAgent-JS-Injection", "X-Page-Speed", "X-Php-Version", "X-Powered-By",
    "X-Powered-By-Plesk", "X-Powered-CMS", "X-Redirect-By", "X-Server-Powered-By",
    "X-SourceFiles", "X-SourceMap", "X-Turbo-Charged-By", "X-Umbraco-Version",
    "X-Varnish-Backend", "X-Varnish-Server", "X-Woodpecker-Version",
    "X-dtAgentId", "X-dtHealthCheck", "X-dtInjectedServlet", "X-ruxit-JS-Agent",
]



###################### DNS / WHOIS (PASSIVE) ######################

#Tipos de registros DNS a consultar
TIPOS_REGISTROS_DNS: List[str] = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]



###################### TECH STACK (PASSIVE) ######################

#URL de la extensión de Wappalyzer para identificación manual de tecnologías
URL_WAPPALYZER: str = "https://www.wappalyzer.com/apps/"



###################### CONFIGURACIÓN DE LOGGING ######################

FORMATO_LOG: str = (
    "<green>{time:HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<level>{message}</level>"
)

#Formato de logs para el archivo
FORMATO_LOG_ARCHIVO: str = (
    "{time:DD-MM-YYYY HH:mm:ss} | "
    "{level: <8} | "
    "{name}:{function}:{line} | "
    "{message}"
)


###################### CONFIGURACIÓN DEL PROYECTO ######################

#Nombre del proyecto
NOMBRE_PROYECTO: str = "SODA"

#Versión actual del proyecto
VERSION: str = "1.0.0"

#Módulo de mapeo usado por defecto cuando se ejecuta --map
#Valores válidos: 'crawler' o 'discoverer'
MODULO_MAPEO_DEFECTO: str = 'discoverer'



###################### CONFIGURACIÓN LLM (VISUALIZER) ######################

#Tokens máximos para la respuesta del LLM 
#Por defecto hay un límite extremadamente alto, se recomienda configurar un límite de gasto en el proveedor
MAX_TOKENS_LLM: int = 128000