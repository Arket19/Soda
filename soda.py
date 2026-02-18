"""
Este módulo es el orquestador principal de la herramienta de reconocimiento web.

Funcionalidades: 
    - Parsear argumentos de línea de comandos
    - Configurar el sistema de logging
    - Orquestar la ejecución de módulos pasivos, activos y de mapeo
    - Gestionar la generación de reportes (JSON, HTML)
"""

import asyncio
import argparse
import json
import sys

from datetime import datetime
from pathlib import Path
from typing import (
    List
)

from urllib.parse import urlparse
from loguru import logger

from core import (
    NOMBRE_PROYECTO,
    VERSION,
    FORMATO_LOG,
    FORMATO_LOG_ARCHIVO,
    MODULO_MAPEO_DEFECTO,
)

from core.session import sesionHttpAsincrona
from core.report_gen import GeneradorReportes
from core.html_report import GeneradorReporteHTML

from modules.passive.dns_whois import DNSRecon
from modules.passive.headers import HeadersAnalyzer
from modules.passive.tech_stack import TechStack

from modules.active.waf_detect import WAFDetect

from modules.map.crawler import Crawler
from modules.map.discoverer import Discoverer
from modules.map.visualizer import Visualizer


#Logging
def configurar_logging(
    modo_detallado: bool = False,
    directorio_salida: Path = None
) -> None:
    """
    Qué hace:
        Configura el sistema de logging de la aplicación usando loguru.
        Establece tanto la salida por consola como la escritura a archivo.

    Argumentos:
        - modo_detallado: Si es True, muestra logs de nivel DEBUG. 
                          Si es False, solo muestra INFO y superiores.
        - directorio_salida: Directorio donde guardar el archivo de log.

    Variables:
        - nivel: Nivel de logging ('DEBUG' o 'INFO').
        - archivo_log: Ruta completa al archivo de log.
        - carpeta_logs: Directorio donde se guardan los logs si no se especifica otro.

    """
    
    #Se elimina el handler por defecto de loguru para poder configurarlo desde cero
    logger.remove()
    
    #Se determina el nivel de logging según el modo
    if modo_detallado:
        nivel = "DEBUG"
    else:
        nivel = "INFO"
    
    #Se configura la salida por consola
    logger.add(
        sys.stderr,
        format=FORMATO_LOG,
        level=nivel,
        colorize=True,
    )
    
    #Se determina dónde guardar el archivo de log
    archivo_log = directorio_salida / "scan.log"

    #Se configura el archivo de logs
    logger.add(
        str(archivo_log),
        format=FORMATO_LOG_ARCHIVO,
        level="DEBUG",
        rotation="10 MB",
    )


#Argumentos
def parsear_argumentos() -> argparse.Namespace:
    """
    Qué hace:
        Parsea los argumentos de línea de comandos del usuario.

    Variables:
        - parser: Objeto ArgumentParser que define los argumentos disponibles.
        - grupo_escaneo: Grupo de argumentos para escaneos agrupados.
        - grupo_pasivos: Grupo de argumentos para módulos pasivos individuales.
        - grupo_activos: Grupo de argumentos para módulos activos individuales.
        - grupo_mapeo: Grupo de argumentos para módulos de mapeo individuales.
        - grupo_opciones_mapeo: Opciones de configuración del crawler.
        - grupo_reporte: Opciones relacionadas con la generación de reportes.
        - argumentos: Resultado del parseo de argumentos.

    Retorna:
        Namespace con todos los argumentos parseados.
    """
    
    #Se crea el parser principal
    parser = argparse.ArgumentParser(
        description=f"{NOMBRE_PROYECTO} v{VERSION} - Herramienta de reconocimiento web",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    
    #Argumento requerido: URL objetivo
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="URL objetivo para el reconocimiento",
    )
    
    
    
    #Escaneo por grupos
    grupo_escaneo = parser.add_argument_group("Escaneo por grupos")
    
    grupo_escaneo.add_argument(
        "--passive",
        action="store_true",
        help="Ejecutar TODOS los módulos pasivos",
    )
    
    grupo_escaneo.add_argument(
        "--active",
        action="store_true",
        help="Ejecutar TODOS los módulos activos",
    )
    
    grupo_escaneo.add_argument(
        "--map",
        action="store_true",
        help="Ejecutar discoverer/crawler (revisar configuración) y el resto de módulos de mapeo"
    )
    
    
    
    #Módulos pasivos individuales
    grupo_pasivos = parser.add_argument_group("Módulos Pasivos")
    
    grupo_pasivos.add_argument(
        "--dns",
        action="store_true",
        help="Ejecutar reconocimiento DNS",
    )
    
    grupo_pasivos.add_argument(
        "--headers",
        action="store_true",
        help="Ejecutar análisis de cabeceras HTTP de seguridad",
    )
    
    grupo_pasivos.add_argument(
        "--tech",
        action="store_true",
        help="Identificar tecnologías utilizadas (no automatizado)",
    )
    
    
    
    #Módulos activos individuales
    grupo_activos = parser.add_argument_group("Módulos Activos individuales")
    
    grupo_activos.add_argument(
        "--waf",
        action="store_true",
        help="Ejecutar detección de WAF",
    )
    
    
    
    #Módulos de mapeo individuales
    grupo_mapeo = parser.add_argument_group("Módulos de Mapeo")
    
    grupo_mapeo.add_argument(
        "--crawler",
        action="store_true",
        help="Ejecutar el crawler web (incompatible con --discoverer)",
    )
    
    grupo_mapeo.add_argument(
        "--discoverer",
        action="store_true",
        help="Ejecutar el discoverer web (incompatible con --crawler)",
    )
    
    grupo_mapeo.add_argument(
        "--visualizer",
        action="store_true",
        help="Ejecutar el visualizador (requiere crawler o discoverer previo)",
    )


    
    #Opciones compartidas por --crawler y --discoverer
    grupo_opciones_mapeo = parser.add_argument_group("Opciones de --crawler y --discoverer")

    grupo_opciones_mapeo.add_argument(
        "-D", "--depth",
        type=int,
        default=3,
        help="Profundidad maxima de exploracion (default: 3)",
    )

    grupo_opciones_mapeo.add_argument(
        "-E", "--exclude",
        nargs="+",
        help="Rutas a excluir (ej: /admin /api)",
    )

    grupo_opciones_mapeo.add_argument(
        "-T", "--timeout",
        type=int,
        default=10,
        help="Timeout en segundos por peticion (default: 5)",
    )

    grupo_opciones_mapeo.add_argument(
        "-W", "--wait",
        type=float,
        default=1.0,
        help="Espera base entre peticiones en segundos (default: 1.0)",
    )

    grupo_opciones_mapeo.add_argument(
        "--include-robots",
        action="store_true",
        help="[Solo --crawler] Incluir URLs de robots.txt como rutas de profundidad 1",
    )

    grupo_opciones_mapeo.add_argument(
        "--include-sitemaps",
        action="store_true",
        help="[Solo --crawler] Incluir URLs de sitemaps como rutas de profundidad 1",
    )

    grupo_opciones_mapeo.add_argument(
        "--max-urls",
        type=int,
        default=30,
        help="[Solo --discoverer] Maximo de URLs por directorio antes de truncar con /* (default: 30)",
    )



    #Opciones de --visualizer
    grupo_opciones_visualizer = parser.add_argument_group("Opciones de --visualizer")

    grupo_opciones_visualizer.add_argument(
        "-K", "--key",
        type=str,
        help="API key para el visualizer",
    )

    grupo_opciones_visualizer.add_argument(
        "-M", "--model",
        type=str,
        help="Modelo LLM a utilizar para el visualizer (Ejemplo: openrouter/openai/gpt-5.1-chat)",
    )



    #Opciones de reporte
    grupo_reporte = parser.add_argument_group("Opciones de Reporte")
    
    grupo_reporte.add_argument(
        "-o", "--output",
        type=str,
        help="Directorio de salida personalizado (default: reports/domain)",
    )
    
    grupo_reporte.add_argument(
        "--report-update",
        action="store_true",
        help="Regenerar HTML desde JSON existente sin ejecutar escaneos",
    )
    
    
    
    #Opciones generales
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Modo verbose (muestra logs DEBUG)",
    )
    
    parser.add_argument(
        "-p", "--proxy",
        type=str,
        help="URL del proxy (ej: http://127.0.0.1:8080)",
    )
    
    
    
    
    #Se parsean los argumentos
    argumentos = parser.parse_args()
    
    #Se valida que --crawler y --discoverer no se usen a la vez
    if argumentos.crawler and argumentos.discoverer:
        parser.error("--crawler y --discoverer son incompatibles. Usa solo uno de los dos.")

    #Se valida que al menos un módulo esté seleccionado o sea --report-update
    ningun_modulo_seleccionado = not any([
        argumentos.passive,
        argumentos.active,
        argumentos.map,
        argumentos.dns,
        argumentos.headers,
        argumentos.tech,
        argumentos.waf,
        argumentos.crawler,
        argumentos.discoverer,
        argumentos.visualizer,
        argumentos.report_update,
    ])

    if ningun_modulo_seleccionado:
        parser.error("Debes especificar al menos un módulo o --report-update. Usa -h para ver opciones.")
    
    return argumentos


#Ejecución de módulos
async def ejecutar_modulos_pasivos(
    url: str,
    sesion: sesionHttpAsincrona,
    reporte: GeneradorReportes,
) -> None:
    """
    Qué hace:
        Ejecuta todos los módulos de reconocimiento pasivo de forma agrupada.
        Los módulos pasivos NO interactúan agresivamente con el objetivo.

    Argumentos:
        - url: URL objetivo del escaneo.
        - sesion: Objeto sesionHttpAsincrona para hacer peticiones HTTP.
        - reporte: Objeto GeneradorReportes donde se centralizan los hallazgos.
    """
    
    logger.info("SODA       | Iniciando modulos PASIVOS")
    
    #Se crea la lista de tareas a ejecutar en paralelo y la lista de módulos
    tareas = []
    
    #DNS/WHOIS
    modulo_dns = DNSRecon()
    tareas.append(modulo_dns.run(url, sesion, reporte))
    
    #Headers
    modulo_headers = HeadersAnalyzer()
    tareas.append(modulo_headers.run(url, sesion, reporte))
    
    #Tech Stack
    modulo_tech = TechStack()
    tareas.append(modulo_tech.run(url, sesion, reporte))
    
    
    
    #Se ejecutan todas las tareas en paralelo
    resultados = await asyncio.gather(*tareas, return_exceptions=True)
    


    nombres_modulos = ["dns_whois", "headers", "tech_stack"]
    
    for i in range(len(resultados)):
        resultado = resultados[i]
        nombre_modulo = nombres_modulos[i]

        #Se verifica si el resultado es una excepción
        if isinstance(resultado, Exception):
            logger.error(f"SODA       | Error en módulo {nombre_modulo}: {resultado}")
            continue

        if resultado:
            logger.info(f"{nombre_modulo.upper(): <10} | Modulo {nombre_modulo} completado")

    logger.info("SODA       | Modulos PASIVOS finalizados")



async def ejecutar_pasivos_individuales(
    modulos_seleccionados: List[str],
    url: str,
    sesion: sesionHttpAsincrona,
    reporte: GeneradorReportes,
) -> None:
    """
    Qué hace:
        Ejecuta módulos pasivos individuales seleccionados por el usuario.

    Argumentos:
        - modulos_seleccionados: Lista con nombres de módulos a ejecutar.
        - url: URL objetivo del escaneo.
        - sesion: Objeto sesionHttpAsincrona para hacer peticiones HTTP.
        - reporte: Objeto GeneradorReportes donde se centralizan los hallazgos.
    """
    
    logger.info(f"SODA       | Ejecutando modulos pasivos individuales: {', '.join(modulos_seleccionados)}")
    
    #Se itera sobre los módulos seleccionados
    for nombre_modulo in modulos_seleccionados:
        
        #DNS
        if nombre_modulo == "dns":
            modulo = DNSRecon()
            resultado = await modulo.run(url, sesion, reporte)
            if resultado:
                logger.info("DNS_WHOIS  | Modulo dns_whois completado")

        #Headers
        elif nombre_modulo == "headers":
            modulo = HeadersAnalyzer()
            resultado = await modulo.run(url, sesion, reporte)
            if resultado:
                logger.info("HEADERS    | Modulo headers completado")

        #Tech Stack
        elif nombre_modulo == "tech":
            modulo = TechStack()
            resultado = await modulo.run(url, sesion, reporte)
            if resultado:
                logger.info("TECH_STACK | Modulo tech_stack completado")

    logger.info("SODA       | Modulos pasivos individuales finalizados ")



async def ejecutar_modulos_activos(
    url: str,
    sesion: sesionHttpAsincrona,
    reporte: GeneradorReportes,
) -> None:
    """
    Qué hace:
        Ejecuta todos los módulos de reconocimiento activo de forma agrupada.
        Los módulos activos SÍ interactúan de forma más agresiva con el objetivo.

    Argumentos:
        - url: URL objetivo del escaneo.
        - sesion: Objeto sesionHttpAsincrona para hacer peticiones HTTP.
        - reporte: Objeto GeneradorReportes donde se centralizan los hallazgos.

    Variables:
        - tareas: Lista de coroutines para ejecutar en paralelo.
        - resultados: Lista con los resultados de cada tarea.
    """
    
    logger.info("SODA       | Iniciando modulos ACTIVOS")
    
    #Se crea la lista de tareas a ejecutar en paralelo
    tareas = []

    #WAF Detect
    modulo_waf = WAFDetect()
    tareas.append(modulo_waf.run(url, sesion, reporte))



    #Se ejecutan todas las tareas en paralelo
    resultados = await asyncio.gather(*tareas, return_exceptions=True)



    nombres_modulos = ["waf_detect"]

    for indice in range(len(resultados)):
        resultado = resultados[indice]
        nombre_modulo = nombres_modulos[indice]

        #Se verifica si el resultado es una excepción
        if isinstance(resultado, Exception):
            logger.error(f"SODA       | Error en módulo {nombre_modulo}: {resultado}")
            continue

        if resultado:
            logger.info(f"{nombre_modulo.upper(): <10} | Modulo {nombre_modulo} completado")

    logger.info("SODA       | Modulos ACTIVOS finalizados")



async def ejecutar_activos_individuales(
    modulos_seleccionados: List[str],
    url: str,
    sesion: sesionHttpAsincrona,
    reporte: GeneradorReportes,
) -> None:
    """
    Qué hace:
        Ejecuta módulos activos individuales seleccionados por el usuario.

    Argumentos:
        - modulos_seleccionados: Lista con nombres de módulos a ejecutar.
        - url: URL objetivo del escaneo.
        - sesion: Objeto sesionHttpAsincrona para hacer peticiones HTTP.
        - reporte: Objeto GeneradorReportes donde se centralizan los hallazgos.

    Variables:
        - nombre_modulo: Nombre del módulo actual en la iteración.
        - modulo: Instancia del módulo a ejecutar.
        - resultado: Datos retornados por el módulo.
    """
    
    logger.info(f"SODA       | Ejecutando modulos activos individuales: {', '.join(modulos_seleccionados)}")
    
    #Se itera sobre los módulos seleccionados
    for nombre_modulo in modulos_seleccionados:
        
        #WAF Detect
        if nombre_modulo == "waf":
            modulo = WAFDetect()
            resultado = await modulo.run(url, sesion, reporte)
            if resultado:
                logger.info("WAF_DETECT | Modulo waf_detect completado")

    logger.info("SODA       | Modulos activos individuales finalizados")



async def ejecutar_modulos_mapeo(
    url: str,
    sesion: sesionHttpAsincrona,
    reporte: GeneradorReportes,
    directorio_salida: Path,
    profundidad_maxima: int = 3,
    rutas_excluidas: List[str] = None,
    timeout: int = 5,
    espera_base: float = 1.0,
    clave_api: str = None,
    modelo_llm: str = None,
    incluir_robots: bool = False,
    incluir_sitemaps: bool = False,
) -> None:
    """
    Qué hace:
        Ejecuta los módulos de mapeo (crawler y visualizer) de forma secuencial.
        El visualizer depende de los resultados del crawler.

    Argumentos:
        - url: URL objetivo del escaneo.
        - sesion: Objeto sesionHttpAsincrona (puede ser None para visualizer).
        - reporte: Objeto GeneradorReportes donde se centralizan los hallazgos.
        - directorio_salida: Directorio donde guardar archivos generados.
        - profundidad_maxima: Profundidad máxima del crawler.
        - rutas_excluidas: Lista de rutas a excluir del crawleo.
        - timeout: Timeout en segundos para peticiones.
        - espera_base: Tiempo de espera base entre peticiones.
        - clave_api: API key para el servicio LLM.
        - modelo_llm: Modelo LLM a utilizar para el visualizer.

    Variables:
        - modulo_crawler: Instancia del módulo Crawler.
        - resultado_crawler: Datos retornados por el crawler.
        - modulo_visualizer: Instancia del módulo Visualizer.
        - resultado_visualizer: Datos retornados por el visualizer.
    """

    logger.info("SODA       | Iniciando modulos de MAPEO")

    if rutas_excluidas is None:
        rutas_excluidas = []

    #Se elige el módulo de exploración (revisar configuracion en core/__init__.py)
    if MODULO_MAPEO_DEFECTO == 'discoverer':
        modulo_exploracion = Discoverer(
            delay_base=espera_base,
            timeout=timeout,
        )
        resultado_mapeo = await modulo_exploracion.run(
            url, sesion, reporte,
            profundidad_maxima=profundidad_maxima,
            rutas_excluidas=rutas_excluidas,
        )
    else:
        modulo_exploracion = Crawler(
            delay_base=espera_base,
            timeout=timeout,
        )
        resultado_mapeo = await modulo_exploracion.run(
            url, sesion, reporte,
            profundidad_maxima=profundidad_maxima,
            rutas_excluidas=rutas_excluidas,
            incluir_robots=incluir_robots,
            incluir_sitemaps=incluir_sitemaps,
        )

    if MODULO_MAPEO_DEFECTO == "discoverer":
        logger.info(f"DISCOVERER | Modulo discoverer completado")
    else:
        logger.info(f"CRAWLER    | Modulo crawler completado")


    #Se ejecuta el visualizer
    modulo_visualizer = Visualizer(
        directorio_salida=str(directorio_salida),
        clave_api=clave_api,
        modelo=modelo_llm,
    )

    resultado_visualizer = await modulo_visualizer.run(url, None, reporte)

    if resultado_visualizer:
        reporte.añadir_hallazgo("visualizer", "map", resultado_visualizer)
        logger.info("VISUALIZER | Modulo visualizer completado")

    logger.info("SODA       | Modulos de MAPEO finalizados")



async def ejecutar_mapeo_individual(
    modulos_seleccionados: List[str],
    url: str,
    reporte: GeneradorReportes,
    directorio_salida: Path,
    profundidad_maxima: int = 3,
    rutas_excluidas: List[str] = None,
    timeout: int = 10,
    espera_base: float = 1.0,
    clave_api: str = None,
    modelo_llm: str = None,
    incluir_robots: bool = False,
    incluir_sitemaps: bool = False,
    max_urls_directorio: int = 30,
) -> None:
    """
    Qué hace:
        Ejecuta módulos de mapeo individuales seleccionados por el usuario.

    Argumentos:
        - modulos_seleccionados: Lista con nombres de módulos a ejecutar.
        - url: URL objetivo del escaneo.
        - reporte: Objeto GeneradorReportes donde se centralizan los hallazgos.
        - directorio_salida: Directorio donde guardar archivos generados.
        - profundidad_maxima: Profundidad máxima del crawler.
        - rutas_excluidas: Lista de rutas a excluir del crawleo.
        - timeout: Timeout en segundos para peticiones.
        - espera_base: Tiempo de espera base entre peticiones.
        - clave_api: API key para el servicio LLM.

    Variables:
        - nombre_modulo: Nombre del módulo actual en la iteración.
        - modulo: Instancia del módulo a ejecutar.
        - resultado: Datos retornados por el módulo.
    """
    
    logger.info(f"SODA       | Ejecutando modulos de mapeo individuales: {', '.join(modulos_seleccionados)}")
    
    if rutas_excluidas is None:
        rutas_excluidas = []
    
    #Se itera sobre los módulos seleccionados
    for nombre_modulo in modulos_seleccionados:
        
        #Crawler
        if nombre_modulo == "crawler":
            modulo = Crawler(
                delay_base=espera_base,
                timeout=timeout,
            )
            resultado = await modulo.run(
                url, None, reporte,
                profundidad_maxima=profundidad_maxima,
                rutas_excluidas=rutas_excluidas,
                incluir_robots=incluir_robots,
                incluir_sitemaps=incluir_sitemaps,
            )
            if resultado:
                logger.info("CRAWLER    | Modulo crawler completado")


        #Discoverer
        elif nombre_modulo == "discoverer":
            modulo = Discoverer(
                delay_base=espera_base,
                timeout=timeout,
            )
            resultado = await modulo.run(
                url, None, reporte,
                profundidad_maxima=profundidad_maxima,
                rutas_excluidas=rutas_excluidas,
                max_urls_directorio=max_urls_directorio,
            )
            if resultado:
                logger.info("DISCOVERER | Modulo discoverer completado")


        #Visualizer
        elif nombre_modulo == "visualizer":
            modulo = Visualizer(
                directorio_salida=str(directorio_salida),
                clave_api=clave_api,
                modelo=modelo_llm,
            )
            resultado = await modulo.run(url, None, reporte)
            if resultado:
                reporte.añadir_hallazgo("visualizer", "map", resultado)
                logger.info("VISUALIZER | Modulo visualizer completado")

    logger.info("SODA       | Modulos de mapeo individuales finalizados")


#Actualizar HTML
def regenerar_html_desde_json(
    ruta_json: Path,
    ruta_html: Path,
) -> bool:
    """
    Qué hace:
        Regenera el reporte HTML a partir de un archivo JSON existente.
        Útil cuando solo se quiere actualizar el HTML sin re-ejecutar escaneos.

    Argumentos:
        - ruta_json: Ruta al archivo JSON del reporte.
        - ruta_html: Ruta donde guardar el HTML generado.

    Variables:
        - archivo: Handle del archivo JSON abierto.
        - datos_json: Contenido parseado del JSON.
        - url_objetivo: URL objetivo extraída de los metadatos.
        - reporte_temporal: Objeto GeneradorReportes temporal.
        - generador_html: Objeto GeneradorReporteHTML.

    Retorna:
        True si se regeneró correctamente, False si hubo error.
    """
    
    #Se verifica que el JSON existe
    if not ruta_json.exists():
        logger.error(f"SODA       | No se encontró el archivo JSON: {ruta_json}")
        return False
    
    try:
        #Se carga el JSON
        with open(ruta_json, "r", encoding="utf-8") as archivo:
            datos_json = json.load(archivo)
        
        #Se extrae la URL objetivo
        url_objetivo = datos_json.get("metadatos", {}).get("objetivo", "unknown")
        
        #Se crea un GeneradorReportes temporal
        reporte_temporal = GeneradorReportes(url_objetivo=url_objetivo)
        
        #Se cargan los hallazgos del JSON
        reporte_temporal.cargar_reporte_existente(str(ruta_json))
        
        #Se genera el HTML
        generador_html = GeneradorReporteHTML(reporte_temporal)
        generador_html.generate(str(ruta_html))
        
        logger.info(f"SODA       | HTML regenerado exitosamente: {ruta_html}")
        
        return True
    
    except Exception as error:
        logger.error(f"SODA       | Error regenerando HTML: {error}")
        return False



async def main() -> None:
    """
    Qué hace:
        Función principal que orquesta toda la ejecución de la herramienta.

    Variables:
        - argumentos: Namespace con los argumentos parseados.
        - url_parseada: Objeto ParseResult con la URL parseada.
        - dominio: Dominio extraído de la URL.
        - timestamp: Timestamp actual para nombres de carpeta.
        - directorio_salida: Path al directorio de salida.
        - pasivos_individuales: Lista de módulos pasivos seleccionados.
        - activos_individuales: Lista de módulos activos seleccionados.
        - mapeo_individual: Lista de módulos de mapeo seleccionados.
        - modos: Lista de modos para mostrar en el banner.
        - ruta_json_reporte: Ruta al archivo JSON del reporte.
        - ruta_html_reporte: Ruta al archivo HTML del reporte.
        - reporte: Objeto GeneradorReportes.
        - necesita_sesion_async: Booleano que indica si se necesita sesión HTTP.
        - verificar_ssl: Booleano que indica si verificar SSL.
        - sesion: Objeto sesionHttpAsincrona.
        - generador_html: Objeto GeneradorReporteHTML.
        - exito: Booleano que indica si se regeneró el HTML correctamente.

    Flujo de ejecución:
        1. Se parsean los argumentos
        2. Se normaliza la URL
        3. Se crea el directorio de salida
        4. Se configura el logging
        5. Se detectan módulos individuales
        6. Se muestra el banner
        7. Se definen rutas de reportes
        8. Si es --report-update, se regenera HTML y se termina
        9. Se crea el GeneradorReportes
        10. Se cargan reportes previos si existen
        11. Se ejecutan los módulos según configuración
        12. Se exportan los reportes
        13. Se manejan excepciones (Ctrl+C, errores)
    """
    
    #Se parsean argumentos
    argumentos = parsear_argumentos()
    
    #Se parsea la URL
    url_parseada = urlparse(argumentos.url)
    
    #Se añade esquema si no tiene
    if not url_parseada.scheme:
        argumentos.url = "https://" + argumentos.url
        url_parseada = urlparse(argumentos.url)
    
    #Se sanitiza el dominio y el path para que puedan ser un nombre de carpeta
    caracteres_invalidos = ':/\\<>"|?*'

    dominio = url_parseada.netloc
    for caracter in caracteres_invalidos:
        dominio = dominio.replace(caracter, "_")

    path_url = url_parseada.path.strip("/")
    if path_url:
        path_sanitizado = path_url
        for caracter in caracteres_invalidos:
            path_sanitizado = path_sanitizado.replace(caracter, "_")
        nombre_carpeta = f"{dominio}_{path_sanitizado}"
    else:
        nombre_carpeta = dominio
        


    #Se crea el directorio de salida para reportes y logs
    if argumentos.output:
        directorio_salida = Path(argumentos.output)
    else:
        directorio_salida = Path("reports") / nombre_carpeta
    
    directorio_salida.mkdir(parents=True, exist_ok=True)
    
    
    
    #Se configura el logging
    configurar_logging(
        modo_detallado=argumentos.verbose,
        directorio_salida=directorio_salida
    )

    
    
    #Se crea la lista de módulos pasivos individuales
    pasivos_individuales = []
    if argumentos.dns:
        pasivos_individuales.append("dns")
    if argumentos.headers:
        pasivos_individuales.append("headers")
    if argumentos.tech:
        pasivos_individuales.append("tech")
    
    #Se crea la lista de módulos activos individuales
    activos_individuales = []
    if argumentos.waf:
        activos_individuales.append("waf")
    
    #Se crea la lista de módulos de mapeo individuales
    mapeo_individual = []
    if argumentos.crawler:
        mapeo_individual.append("crawler")
    if argumentos.discoverer:
        mapeo_individual.append("discoverer")
    if argumentos.visualizer:
        mapeo_individual.append("visualizer")
    


    #Se imprime el banner de la aplicación por consola
    modos = []
    if argumentos.passive:
        modos.append("Pasivo")
    if argumentos.active:
        modos.append("Activo")
    if argumentos.map:
        modos.append("Mapeo")
    if pasivos_individuales:
        modos.append(f"Individual({', '.join(pasivos_individuales)})")
    if activos_individuales:
        modos.append(f"Individual({', '.join(activos_individuales)})")
    if mapeo_individual:
        modos.append(f"Individual({', '.join(mapeo_individual)})")
    if argumentos.report_update:
        modos.append("Report-Update")

    print(f"\n{'=' * 60}")
    print(f"  {NOMBRE_PROYECTO} v{VERSION}")
    print(f"{'=' * 60}")
    print(f"  Objetivo: {argumentos.url}")
    
    if modos:
        print(f"  Modo: {' | '.join(modos)}")
    else:
        print(f"  Modo: Ninguno")
    if argumentos.proxy:
        print(f"  Proxy: {argumentos.proxy}")
        
    print(f"  Salida: {directorio_salida}")
    print(f"{'=' * 60}\n")
    


    #Se definen las rutas de los reportes que se van a generar
    ruta_json_reporte = directorio_salida / "report.json"
    ruta_html_reporte = directorio_salida / "report.html"
    

    
    #Si el modo es --report-update, se actualiza el informe con los datos del JSON
    if argumentos.report_update:
        logger.info("SODA       | Modo --report-update: Regenerando HTML desde JSON existente...")
        exito = regenerar_html_desde_json(ruta_json_reporte, ruta_html_reporte)
        if exito:
            logger.info(f"SODA       | Reporte actualizado en: {directorio_salida}")
        else:
            logger.error("SODA       | No se pudo regenerar el reporte HTML")
            sys.exit(1)
        return
    

    #Se crea el generador de reportes o se carga el anterior si ya existe
    reporte = GeneradorReportes(url_objetivo=argumentos.url)
    
    #Se carga el reporte previo si existe (persistencia incremental)
    if ruta_json_reporte.exists():
        reporte.cargar_reporte_existente(str(ruta_json_reporte))
        logger.info(f"SODA       | Reporte previo cargado desde: {ruta_json_reporte}")
    
    
    
    
    #Ejecución de módulos
    try:
        #Se determina si es necesaria una sesión HTTP asíncrona
        necesita_sesion_async = (
            argumentos.passive or 
            argumentos.active or 
            pasivos_individuales or 
            activos_individuales
        )
        
        #Se ejecuta la herramienta según las necesidades de sincronía
        if necesita_sesion_async:
            #Se crea la sesión HTTP con configuración SSL
            verificar_ssl = not bool(argumentos.proxy)
            
            async with sesionHttpAsincrona(proxy=argumentos.proxy, verificar_ssl=verificar_ssl) as sesion:
                
                #Ejecutar módulos pasivos agrupados
                if argumentos.passive:
                    await ejecutar_modulos_pasivos(argumentos.url, sesion, reporte)
                
                #Ejecutar módulos pasivos individuales
                if pasivos_individuales:
                    await ejecutar_pasivos_individuales(pasivos_individuales, argumentos.url, sesion, reporte)
                
                #Ejecutar módulos activos agrupados
                if argumentos.active:
                    await ejecutar_modulos_activos(argumentos.url, sesion, reporte)
                
                #Ejecutar módulos activos individuales
                if activos_individuales:
                    await ejecutar_activos_individuales(activos_individuales, argumentos.url, sesion, reporte)
                
                #Ejecutar módulos de mapeo agrupados
                if argumentos.map:
                    await ejecutar_modulos_mapeo(
                        argumentos.url, sesion, reporte, directorio_salida,
                        profundidad_maxima=argumentos.depth,
                        rutas_excluidas=argumentos.exclude or [],
                        timeout=argumentos.timeout,
                        espera_base=argumentos.wait,
                        clave_api=argumentos.key,
                        modelo_llm=argumentos.model,
                        incluir_robots=argumentos.include_robots,
                        incluir_sitemaps=argumentos.include_sitemaps,
                    )

                #Ejecutar módulos de mapeo individuales
                if mapeo_individual:
                    await ejecutar_mapeo_individual(
                        mapeo_individual, argumentos.url, reporte, directorio_salida,
                        profundidad_maxima=argumentos.depth,
                        rutas_excluidas=argumentos.exclude or [],
                        timeout=argumentos.timeout,
                        espera_base=argumentos.wait,
                        clave_api=argumentos.key,
                        modelo_llm=argumentos.model,
                        incluir_robots=argumentos.include_robots,
                        incluir_sitemaps=argumentos.include_sitemaps,
                        max_urls_directorio=argumentos.max_urls,
                    )
        else:
            #Sin sesión async: solo módulos de mapeo
            if argumentos.map:
                await ejecutar_modulos_mapeo(
                    argumentos.url, None, reporte, directorio_salida,
                    profundidad_maxima=argumentos.depth,
                    rutas_excluidas=argumentos.exclude or [],
                    timeout=argumentos.timeout,
                    espera_base=argumentos.wait,
                    clave_api=argumentos.key,
                    modelo_llm=argumentos.model,
                    incluir_robots=argumentos.include_robots,
                    incluir_sitemaps=argumentos.include_sitemaps,
                )

            if mapeo_individual:
                await ejecutar_mapeo_individual(
                    mapeo_individual, argumentos.url, reporte, directorio_salida,
                    profundidad_maxima=argumentos.depth,
                    rutas_excluidas=argumentos.exclude or [],
                    timeout=argumentos.timeout,
                    espera_base=argumentos.wait,
                    clave_api=argumentos.key,
                    modelo_llm=argumentos.model,
                    incluir_robots=argumentos.include_robots,
                    max_urls_directorio=argumentos.max_urls,
                    incluir_sitemaps=argumentos.include_sitemaps,
                )
        

        #Se generan los reportes
        reporte.exportar_json(str(ruta_json_reporte))

        generador_html = GeneradorReporteHTML(reporte)
        generador_html.generate(str(ruta_html_reporte))
        
        logger.info(f"SODA       | Reportes guardados en: {directorio_salida}")
        
    except KeyboardInterrupt:
        #El usuario interrumpió el escaneo con Ctrl+C
        logger.warning("SODA       | Escaneo interrumpido por el usuario")
        
        #Se guarda el progreso antes de salir
        reporte.exportar_json(str(ruta_json_reporte))
        logger.info(f"SODA       | Progreso guardado en: {ruta_json_reporte}")
        sys.exit(1)
        
    except Exception as error:
        logger.error(f"SODA       | Error durante el escaneo: {error}")
        sys.exit(1)



if __name__ == "__main__":
    asyncio.run(main())