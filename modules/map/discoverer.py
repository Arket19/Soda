"""
Este módulo descubre la estructura de una web mediante exploración
por niveles de profundidad de directorio.

Funcionalidades:
    - Obtención de robots.txt y sitemaps.
    - Clasificación de URLs por profundidad de directorio.
    - Control de densidad: trunca directorios con más de --max-urls hijos directos.
    - Detección de subdominios y extracción de parámetros GET.

"""

import asyncio
import time
import random
import re

from loguru import logger
from curl_cffi import requests
from curl_cffi.requests import Session
from bs4 import BeautifulSoup
from urllib.parse import (
    urljoin,
    urlparse,
    parse_qs,
)
from typing import (
    Optional,
    Dict,
    List,
    Set,
    Any,
)
from core import (
    LISTA_USER_AGENTS,
    SUPLANTACIONES_NAVEGADOR,
    EXTENSIONES_ESTATICAS,
    DELAY_BASE_CRAWLER,
    RANGO_JITTER_CRAWLER,
    MAX_REINTENTOS_CRAWLER,
    TIMEOUT_CRAWLER,
    BASE_BACKOFF,
    MAX_URLS_DIRECTORIO,
)
from core.session import sesionHttpAsincrona
from core.report_gen import GeneradorReportes



class Discoverer:
    """
    Qué hace:
        Mapea la estructura de un sitio clasificando las URLs por profundidad
        de directorio. Implementa las mismas técnicas anti-detección que el
        crawler para evitar bloqueos por WAFs.

    Atributos específicos de la clase:
        - LISTA_USER_AGENTS: Lista de User-Agents de navegadores reales.
        - SUPLANTACIONES_NAVEGADOR: Navegadores a suplantar con curl_cffi.
        - EXTENSIONES_ESTATICAS: Extensiones de archivos estáticos a ignorar.
    """

    NOMBRE_MODULO: str = "discoverer"
    CATEGORIA: str = "map"

    LISTA_USER_AGENTS = LISTA_USER_AGENTS
    SUPLANTACIONES_NAVEGADOR = SUPLANTACIONES_NAVEGADOR
    EXTENSIONES_ESTATICAS = EXTENSIONES_ESTATICAS



    def __init__(
        self,
        delay_base: float = DELAY_BASE_CRAWLER,
        rango_jitter: tuple = RANGO_JITTER_CRAWLER,
        max_reintentos: int = MAX_REINTENTOS_CRAWLER,
        timeout: int = TIMEOUT_CRAWLER,
    ) -> None:
        """
        Qué hace:
            Inicializa el discoverer con la configuración de red y anti-detección.

        Argumentos:
            - delay_base: Tiempo base entre peticiones (segundos).
            - rango_jitter: Rango (min, max) para aleatorizar el delay.
            - max_reintentos: Número máximo de reintentos por petición fallida.
            - timeout: Tiempo máximo de espera por petición (segundos).

        Atributos de instancia creados:
            - self.delay_base: Almacena el delay base entre peticiones.
            - self.rango_jitter: Almacena el rango de variación del delay.
            - self.max_reintentos: Almacena el número máximo de reintentos.
            - self.timeout: Almacena el timeout por petición.
            - self.sesion: Sesión HTTP (se crea en _ejecutar_descubrimiento_sincrono).
            - self.es_primera_peticion: Flag para no aplicar throttling en la primera.
            - self.historial_referer: Lista de URLs recientes para simular navegación.
            - self._cancelado: Flag para detener el proceso desde el hilo principal.
        """

        #Se configuran los intentos, el delay y el timeout
        self.delay_base = delay_base
        self.rango_jitter = rango_jitter
        self.max_reintentos = max_reintentos
        self.timeout = timeout

        #Se configura el estado inicial del discoverer
        self.sesion: Optional[Session] = None
        self.es_primera_peticion: bool = True
        self.historial_referer: List[str] = []

        #Flag de cancelación para Ctrl+C.
        self._cancelado: bool = False



    async def run(
        self,
        url: str,
        session: sesionHttpAsincrona,
        report: GeneradorReportes,
        profundidad_maxima: int = 3,
        rutas_excluidas: List[str] = None,
        max_urls_directorio: int = MAX_URLS_DIRECTORIO,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Método principal que ejecuta el discoverer de forma asíncrona.

        Argumentos:
            - url: URL objetivo desde donde comenzar el descubrimiento.
            - session: Sesión HTTP asíncrona (no se usa, se mantiene por
                       compatibilidad con la arquitectura de SODA).
            - report: Generador de reportes donde se guardan los hallazgos.
            - profundidad_maxima: Nivel máximo de directorio a descubrir.
            - rutas_excluidas: Lista de rutas a excluir.
            - max_urls_directorio: Máximo de URLs hijas por directorio.

        Variables:
            - event_loop: El event loop de asyncio en ejecución.
            - resultados: Diccionario con los resultados del descubrimiento.

        Retorna:
            Diccionario con los resultados del descubrimiento.
        """

        logger.info(f"DISCOVERER | Iniciando descubrimiento de {url}")
        logger.info(f"DISCOVERER | Profundidad máxima: {profundidad_maxima}, Límite por directorio: {max_urls_directorio}")

        #Se reinicia el flag de cancelación para esta ejecución
        self._cancelado = False

        #Se obtiene el event loop que ya está en ejecución
        event_loop = asyncio.get_running_loop()

        #Se ejecuta el descubrimiento síncrono en un thread de run_in_executor()
        try:
            resultados = await event_loop.run_in_executor(
                None,
                self._ejecutar_descubrimiento_sincrono,
                url,
                profundidad_maxima,
                rutas_excluidas,
                max_urls_directorio,
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            self._cancelado = True
            logger.warning("DISCOVERER | Cancelando descubrimiento...")

            #Se espera brevemente para que el thread termine su iteración actual
            await asyncio.sleep(0.5)
            raise

        #Se añaden los hallazgos al reporte
        report.añadir_hallazgo(
            nombre_modulo=self.NOMBRE_MODULO,
            categoria=self.CATEGORIA,
            datos=resultados,
        )

        logger.info(f"DISCOVERER | Descubrimiento completado. URLs descubiertas: {resultados.get('urls_discovered', 0)}")

        return resultados



    def _ejecutar_descubrimiento_sincrono(
        self,
        url_inicio: str,
        profundidad_maxima: int,
        rutas_excluidas: List[str],
        max_urls_directorio: int,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Wrapper síncrono que inicializa la sesión HTTP y llama al método
            principal de descubrimiento.

        Argumentos:
            - url_inicio: URL inicial desde donde comenzar.
            - profundidad_maxima: Nivel máximo de directorio a descubrir.
            - rutas_excluidas: Lista de rutas a excluir.
            - max_urls_directorio: Máximo de URLs hijas por directorio.

        Variables:
            - resultados: Diccionario con los resultados del descubrimiento.

        Retorna:
            Diccionario con los resultados del descubrimiento.
        """

        try:
            #Se reinicia el estado interno para esta ejecución
            self.es_primera_peticion = True
            self.historial_referer = []

            #Se inicializa la sesión HTTP en el mismo thread donde se usará
            self._inicializar_sesion_HTTP_sincrona()

            #Se ejecuta el descubrimiento principal
            resultados = self._descubrir(
                url_inicio=url_inicio,
                profundidad_maxima=profundidad_maxima,
                rutas_excluidas=rutas_excluidas,
                max_urls_directorio=max_urls_directorio,
            )

            return resultados

        except Exception as error:
            logger.error(f"DISCOVERER | Error durante el descubrimiento: {error}")
            return {
                "urls": [],
                "urls_por_nivel": {},
                "urls_truncadas": [],
                "urls_discovered": 0,
                "max_depth": 0,
                "exclude_paths": rutas_excluidas or [],
                "base_url": url_inicio,
                "subdomains": [],
                "robots_txt": None,
                "sitemap": [],
                "get_params": {},
                "error": str(error),
            }

        finally:
            #Se cierra la sesión HTTP para liberar recursos de red
            self._cerrar_sesion()



    def _cerrar_sesion(self) -> None:
        """
        Qué hace:
            Cierra la sesión HTTP y libera los recursos de red asociados.
        """

        if self.sesion is not None:
            self.sesion.close()
            self.sesion = None
            logger.debug("DISCOVERER | Sesión HTTP del discoverer cerrada")



    def _inicializar_sesion_HTTP_sincrona(self) -> None:
        """
        Qué hace:
            Inicializa una nueva sesión HTTP simulando un navegador real.
            Configura la suplantación de huella TLS/JA3 mediante curl_cffi.

        Variables:
            - navegador: Navegador seleccionado aleatoriamente para suplantación.
        """

        #Se selecciona un navegador aleatorio para suplantar su huella TLS
        navegador = random.choice(self.SUPLANTACIONES_NAVEGADOR)
        self.sesion = Session(impersonate=navegador)

        #Se configuran las cabeceras HTTP para simular una navegación real
        self.sesion.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        })



    def _calcular_delay(self) -> float:
        """
        Qué hace:
            Calcula el tiempo de espera entre peticiones aplicando
            variación aleatoria (jittering) sobre el delay base.

        Variables:
            - jitter: Variación aleatoria dentro del rango configurado.
            - delay: Tiempo de espera final (delay base + jitter).

        Retorna:
            Tiempo de espera en segundos.
        """

        jitter = random.uniform(self.rango_jitter[0], self.rango_jitter[1])
        delay = self.delay_base + jitter

        return delay



    def _esperar(self) -> None:
        """
        Qué hace:
            Aplica throttling entre peticiones esperando un tiempo aleatorio.

        Variables:
            - delay: Tiempo total a esperar (segundos).
            - transcurrido: Tiempo ya transcurrido (segundos).
            - incremento: Fragmento de espera por cada iteración (0.2 segundos).
        """

        delay = self._calcular_delay()
        transcurrido = 0.0

        while transcurrido < delay:
            if self._cancelado:
                return
            incremento = min(0.2, delay - transcurrido)
            time.sleep(incremento)
            transcurrido += incremento



    def _obtener_referer(self, url_actual: str) -> str:
        """
        Qué hace:
            Devuelve un referer realista para la petición.

        Argumentos:
            - url_actual: URL que se va a visitar.

        Variables:
            - url_parseada: Componentes de la URL actual.
            - referer: URL que se usará como cabecera Referer.

        Retorna:
            URL del referer.
        """

        #Si hay historial de navegación, se usa la URL visitada más recientemente
        if self.historial_referer:
            referer = self.historial_referer[-1]

        #Si no hay historial, se parte de la página principal del sitio
        else:
            url_parseada = urlparse(url_actual)
            referer = f"{url_parseada.scheme}://{url_parseada.netloc}/"

        return referer



    def _es_respuesta_html(self, respuesta: requests.Response) -> bool:
        """
        Qué hace:
            Verifica si la respuesta HTTP contiene HTML navegable.

        Argumentos:
            - respuesta: Objeto Response de la petición HTTP.

        Variables:
            - content_type: Valor de la cabecera Content-Type.

        Retorna:
            True si el Content-Type indica HTML, False en caso contrario.
        """

        content_type = respuesta.headers.get('Content-Type', '').lower()

        if 'text/html' in content_type or 'application/xhtml' in content_type:
            return True

        return False



    def _realizar_peticion(
        self,
        url: str,
        metodo: str = 'GET',
        **kwargs,
    ) -> Optional[requests.Response]:
        """
        Qué hace:
            Realiza una petición HTTP con técnicas anti-detección
            y reintento con backoff exponencial

        Argumentos:
            - url: URL a visitar.
            - metodo: Método HTTP (GET por defecto).
            - **kwargs: Argumentos adicionales para la petición.

        Variables:
            - user_agent: User-Agent aleatorio para esta petición.
            - referer: URL de origen simulada.
            - headers: Diccionario de cabeceras HTTP para esta petición.
            - respuesta: Objeto Response de la petición.
            - intento: Número de intento actual (comienza en 0).
            - espera: Tiempo de backoff antes del siguiente reintento.
            - status: Código de estado HTTP de la respuesta.

        Retorna:
            Objeto Response o None si falla después de todos los reintentos.
        """

        #Se ejecuta el throttling, exceptuando en la primera iteracion
        if not self.es_primera_peticion:
            self._esperar()
        self.es_primera_peticion = False

        #Se selecciona un User-Agent aleatorio
        user_agent = random.choice(self.LISTA_USER_AGENTS)

        #Se obtiene un referer realista 
        referer = self._obtener_referer(url)

        #Se configuran las cabeceras de esta petición
        headers = kwargs.pop('headers', {})
        headers['User-Agent'] = user_agent
        headers['Referer'] = referer

        logger.debug(f"DISCOVERER | Fetching: {url}")
        logger.debug(f"DISCOVERER | User-Agent: {user_agent}")

        respuesta = None

        #Reintentos con backoff exponencial
        for intento in range(self.max_reintentos):
            try:
                respuesta = self.sesion.request(
                    method=metodo,
                    url=url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    **kwargs
                )

                #Se verifica que la respuesta sea exitosa
                respuesta.raise_for_status()

                logger.debug(f"DISCOVERER | Código de estado {respuesta.status_code}: {url}")

                #Se actualiza el historial de referer con la URL visitada
                self.historial_referer.append(url)

                #Se mantienen solo las últimas 10 URLs en el historial
                if len(self.historial_referer) > 10:
                    self.historial_referer.pop(0)

                return respuesta

            except Exception as error:
                #Si hay un error 4xx, no se reintenta
                if respuesta is not None:
                    if hasattr(respuesta, 'status_code'):
                        status = respuesta.status_code
                        if status >= 400 and status < 500:
                            logger.debug(f"DISCOVERER | Error HTTP {status}: {url}")
                            return None

                logger.warning(f"DISCOVERER | Intento {intento + 1}/{self.max_reintentos} falló: {error}")

                #Si quedan reintentos se hace backof
                if intento < self.max_reintentos - 1:
                    espera = BASE_BACKOFF * (2 ** intento)
                    logger.debug(f"DISCOVERER | Reintentando en {espera}s...")
                    time.sleep(espera)
                else:
                    logger.error(f"DISCOVERER | Falló después de {self.max_reintentos} intentos: {url}")

        return None



    def _extraer_enlaces(
        self,
        html: str,
        url_base: str,
    ) -> List[str]:
        """
        Qué hace:
            Extrae todos los enlaces válidos de una página HTML, resolviendo
            las URLs relativas y filtrando archivos estáticos.

        Argumentos:
            - html: Contenido HTML de la página.
            - url_base: URL base para resolver enlaces relativos.

        Variables:
            - enlaces: Lista acumulada de enlaces encontrados.
            - soup: Objeto BeautifulSoup para parsear el HTML.
            - etiqueta: Cada elemento HTML que tenga atributo href.
            - href: Valor del atributo href encontrado.
            - url_absoluta: URL convertida de relativa a absoluta.
            - url_parseada: Componentes de la URL encontrada.
            - path_minusculas: Path en minúsculas para comparar extensiones.
            - es_archivo_estatico: Flag para saber si el enlace es un recurso estático.
            - extension: Cada extensión estática de la lista a comprobar.
            - url_limpia: URL normalizada sin fragmentos.
            - vistos: Set para eliminar URLs duplicadas.
            - enlaces_unicos: Lista final sin duplicados.

        Retorna:
            Lista de URLs únicas encontradas en la página.
        """

        enlaces = []

        #Se usa BeautifulSoup con el parser lxml
        soup = BeautifulSoup(html, 'lxml')

        #Se buscan todos los elementos HTML que tengan un atributo href
        for etiqueta in soup.find_all(href=True):
            href = etiqueta['href'].strip()

            #Se ignoran enlaces especiales que no son URLs navegables
            if (href.startswith('javascript:')
                or href.startswith('mailto:')
                or href.startswith('tel:')
                or href.startswith('data:')
                or href.startswith('#')
                or href.startswith('{')):
                continue

            #Se convierte a URL absoluta
            url_absoluta = urljoin(url_base, href)
            url_parseada = urlparse(url_absoluta)

            #Solo se procesan URLs HTTP/HTTPS
            if url_parseada.scheme not in ('http', 'https'):
                continue

            #Se filtran archivos estáticos (imágenes, CSS, JS, etc.)
            path_minusculas = url_parseada.path.lower()
            es_archivo_estatico = False
            for extension in self.EXTENSIONES_ESTATICAS:
                if path_minusculas.endswith(extension):
                    es_archivo_estatico = True
                    break

            if es_archivo_estatico:
                continue

            #Se normaliza la URL eliminando anchors
            url_limpia = f"{url_parseada.scheme}://{url_parseada.netloc}{url_parseada.path}"
            if url_parseada.query:
                url_limpia = url_limpia + f"?{url_parseada.query}"

            enlaces.append(url_limpia)

        #Se eliminan duplicados manteniendo el orden
        vistos = set()
        enlaces_unicos = []
        for enlace in enlaces:
            if enlace not in vistos:
                vistos.add(enlace)
                enlaces_unicos.append(enlace)

        return enlaces_unicos



    def _obtener_robots_txt(self, url_base: str) -> Optional[str]:
        """
        Qué hace:
            Obtiene el contenido del archivo robots.txt del sitio.

        Argumentos:
            - url_base: URL base del sitio.

        Variables:
            - url_parseada: Componentes de la URL base.
            - robots_url: URL completa del archivo robots.txt.
            - respuesta: Respuesta HTTP de la petición.

        Retorna:
            Contenido del robots.txt como texto, o None si no existe o falla.
        """

        url_parseada = urlparse(url_base)
        robots_url = f"{url_parseada.scheme}://{url_parseada.netloc}/robots.txt"

        try:
            respuesta = self._realizar_peticion(robots_url)
            if respuesta is not None and respuesta.status_code == 200:
                return respuesta.text
            return None
        except Exception as error:
            logger.debug(f"DISCOVERER | Error obteniendo robots.txt: {error}")
            return None



    def _extraer_sitemaps_de_robots(self, contenido_robots: str) -> List[str]:
        """
        Qué hace:
            Busca y extrae las URLs de sitemaps declaradas en robots.txt
            mediante las directivas 'Sitemap:'.

        Argumentos:
            - contenido_robots: Contenido completo del archivo robots.txt.

        Variables:
            - sitemaps: Lista acumulada de URLs de sitemaps encontradas.
            - linea: Cada línea del robots.txt durante la iteración.
            - sitemap_url: URL extraída de una línea 'Sitemap:'.

        Retorna:
            Lista de URLs de sitemaps encontradas en robots.txt.
        """

        sitemaps = []

        if not contenido_robots:
            return sitemaps

     #Se recorre cada línea del robots.txt buscando "sitemap:"
        for linea in contenido_robots.split('\n'):
            linea = linea.strip()

            #Si empieza por 'sitemap:' se extrae la URL
            if linea.lower().startswith('sitemap:'):
                sitemap_url = linea.split(':', 1)[1].strip()
                sitemaps.append(sitemap_url)

        return sitemaps



    def _obtener_sitemap(self, sitemap_url: str) -> Optional[str]:
        """
        Qué hace:
            Obtiene el contenido de un archivo sitemap XML.

        Argumentos:
            - sitemap_url: URL del sitemap a descargar.

        Variables:
            - respuesta: Respuesta HTTP de la petición.

        Retorna:
            Contenido del sitemap como texto, o None si falla.
        """

        logger.debug(f"DISCOVERER | Obteniendo sitemap: {sitemap_url}")

        try:
            respuesta = self._realizar_peticion(sitemap_url)
            if respuesta is not None and respuesta.status_code == 200:
                return respuesta.text
            return None
        except Exception as error:
            logger.debug(f"DISCOVERER | Error obteniendo sitemap: {error}")
            return None



    def _parsear_urls_sitemap(self, contenido_sitemap: str) -> List[str]:
        """
        Qué hace:
            Extrae las URLs contenidas en un sitemap XML buscando
            las etiquetas <loc> mediante expresiones regulares.

        Argumentos:
            - contenido_sitemap: Contenido XML del sitemap.

        Variables:
            - urls_sitemap: Lista acumulada de URLs encontradas.
            - patron_loc: Expresión regular para encontrar tags <loc>.
            - coincidencias: Lista de URLs encontradas por el regex.
            - url: Cada URL encontrada durante la iteración.

        Retorna:
            Lista de URLs encontradas en el sitemap.
        """

        urls_sitemap = []

        if not contenido_sitemap:
            return urls_sitemap

        #Patrón regex para extraer contenido de tags <loc>
        patron_loc = r'<loc>\s*([^<]+)\s*</loc>'
        coincidencias = re.findall(patron_loc, contenido_sitemap, re.IGNORECASE)

        for url in coincidencias:
            urls_sitemap.append(url.strip())

        return urls_sitemap



    def _descubrir_urls_sitemap(
        self,
        url_base: str,
        contenido_robots: str = None,
    ) -> Dict[str, List[str]]:
        """
        Qué hace:
            Descubre y extrae todas las URLs de los sitemaps del sitio.
            Primero busca sitemaps en robots.txt, luego prueba rutas comunes.

        Argumentos:
            - url_base: URL base del sitio.
            - contenido_robots: Contenido del robots.txt ya obtenido (opcional).

        Variables:
            - resultado: Diccionario con 'sitemaps' y 'urls' encontradas.
            - sitemap_urls: Lista de URLs de sitemaps a procesar.
            - url_parseada: Componentes de la URL base.
            - sitemaps_comunes: Rutas típicas donde suelen estar los sitemaps.
            - todas_las_urls: Lista acumulada de URLs encontradas en todos los sitemaps.
            - sitemap_url: Cada URL de sitemap a procesar durante la iteración.
            - contenido_sitemap: Contenido XML del sitemap descargado.
            - urls: Lista de URLs extraídas de un sitemap concreto.

        Retorna:
            Diccionario con clave 'sitemaps' (lista de URLs de sitemaps encontrados)
            y 'urls' (lista de todas las URLs encontradas en esos sitemaps).
        """

        resultado = {
            'sitemaps': [],
            'urls': []
        }

         #Se extraen URLs de sitemaps del robots.txt
        if contenido_robots:
            sitemap_urls = self._extraer_sitemaps_de_robots(contenido_robots)
        else:
            sitemap_urls = []

        #Si no hay sitemaps en robots.txt, se prueban ubicaciones comunes
        if not sitemap_urls:
            url_parseada = urlparse(url_base)
            sitemaps_comunes = [
                f"{url_parseada.scheme}://{url_parseada.netloc}/sitemap.xml",
                f"{url_parseada.scheme}://{url_parseada.netloc}/sitemap_index.xml",
            ]
            sitemap_urls = sitemaps_comunes

        #Se procesa cada sitemap encontrado
        todas_las_urls = []
        for sitemap_url in sitemap_urls:
            contenido_sitemap = self._obtener_sitemap(sitemap_url)
            if contenido_sitemap:
                resultado['sitemaps'].append(sitemap_url)
                urls = self._parsear_urls_sitemap(contenido_sitemap)
                todas_las_urls.extend(urls)

        #Se eliminan duplicados 
        resultado['urls'] = list(set(todas_las_urls))

        return resultado



    def _es_subdominio(self, url: str, dominio_base: str) -> bool:
        """
        Qué hace:
            Verifica si la URL pertenece a un subdominio del dominio base.

        Argumentos:
            - url: URL a verificar.
            - dominio_base: Dominio base con el que comparar.

        Variables:
            - parseada: Componentes de la URL a verificar.
            - dominio_url: Dominio extraído de la URL, sin el prefijo www.

        Retorna:
            True si es un subdominio (distinto al dominio base pero que
            termina con él), False en caso contrario.
        """

        parseada = urlparse(url)
        dominio_url = parseada.netloc.replace('www.', '')

        #Si es exactamente el mismo dominio, no es un subdominio
        if dominio_url == dominio_base:
            return False

        #Se comprueba si el dominio termina con el dominio base 
        return dominio_url.endswith('.' + dominio_base)



    def _debe_excluirse(
        self,
        url: str,
        rutas_excluidas: List[str],
    ) -> bool:
        """
        Qué hace:
            Verifica si una URL debe ser excluida del descubrimiento
            porque su path contiene alguno de los patrones de exclusión.

        Argumentos:
            - url: URL a verificar.
            - rutas_excluidas: Lista de cadenas que si aparecen en el path
                               de la URL, esta debe excluirse.

        Variables:
            - parseada: Componentes de la URL a verificar.
            - path_minusculas: Path en minúsculas para comparación sin distinción
                               de mayúsculas/minúsculas.
            - excluido: Cada patrón de exclusión durante la iteración.

        Retorna:
            True si la URL debe excluirse, False si debe procesarse.
        """

        parseada = urlparse(url)
        path_minusculas = parseada.path.lower()

        #Se comprueba si la URL contiene algún texto de exclusión
        for excluido in rutas_excluidas:
            if excluido.lower() in path_minusculas:
                return True
            

        return False



    def _obtener_profundidad_url(self, url: str) -> int:
        """
        Qué hace:
            Calcula la profundidad de directorio de una URL contando
            los segmentos no vacíos de su path.

        Argumentos:
            - url: URL cuya profundidad se quiere calcular.

        Variables:
            - path: El path de la URL (todo lo que va después del dominio).
            - partes: Lista de segmentos del path sin elementos vacíos.

        Retorna:
            Número entero con la profundidad de directorio de la URL.
        """

        path = urlparse(url).path

        #Se divide el path por '/' y se eliminan los segmentos vacíos
        partes = [parte for parte in path.split('/') if parte]

        return len(partes)



    def _es_url_directorio(self, url: str) -> bool:
        """
        Qué hace:
            Determina si una URL representa un directorio o un archivo.
            El discoverer solo debe indexar directorios, no archivos con extensión.

        Argumentos:
            - url: URL a evaluar.

        Variables:
            - path: Componente de path de la URL.
            - ultimo_segmento: Último segmento no vacío del path.

        Retorna:
            True si la URL parece un directorio, False si parece un archivo.
        """

        path = urlparse(url).path

        #La raíz siempre es un directorio
        if not path or path == '/':
            return True

        #Si el path termina en /, es un directorio
        if path.endswith('/'):
            return True

        #Se extrae el último segmento del path para comprobar si tiene extensión
        ultimo_segmento = path.rstrip('/').split('/')[-1]
        if '.' in ultimo_segmento:
            return False

        return True



    def _obtener_padre_nivel(self, url: str, nivel: int) -> Optional[str]:
        """
        Qué hace:
            Construye la URL padre de una URL hijo según el nivel de directorio.
            Por ejemplo, el padre de nivel 1 de algo.com/a/b/c es algo.com/a/.

        Argumentos:
            - url: URL original de la que se quiere el padre.
            - nivel: Nivel de directorio del padre deseado (1, 2, 3...).

        Variables:
            - parseada: Componentes de la URL original.
            - partes: Segmentos no vacíos del path de la URL.
            - parent_path: Path reconstruido con los primeros 'nivel' segmentos.

        Retorna:
            URL del padre al nivel indicado, o None si la URL tiene
            menos segmentos de path que el nivel pedido.
        """

        parseada = urlparse(url)

        #Se obtienen los segmentos no vacíos del path
        partes = [parte for parte in parseada.path.split('/') if parte]

        #Si la URL tiene menos profundidad que el nivel pedido, no hay padre
        if len(partes) < nivel:
            return None

        #Se reconstruye el path con solo los primeros 'nivel' segmentos
        parent_path = '/' + '/'.join(partes[:nivel]) + '/'

        return f"{parseada.scheme}://{parseada.netloc}{parent_path}"



    def _descubrir(
        self,
        url_inicio: str,
        profundidad_maxima: int,
        rutas_excluidas: List[str],
        max_urls_directorio: int,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Método principal del discoverer. Implementa el algoritmo de
            descubrimiento por niveles de directorio.

        Argumentos:
            - url_inicio: URL inicial desde donde comenzar.
            - profundidad_maxima: Nivel máximo de directorio a descubrir.
            - rutas_excluidas: Lista de patrones de rutas a excluir.
            - max_urls_directorio: Máximo de hijos por directorio padre.

        Variables:
            - url_base_parseada: Componentes de la URL inicial.
            - dominio_base: Dominio base (sin www) para validar URLs.
            - urls_por_nivel: Diccionario que agrupa URLs por su nivel de directorio.
            - urls_conocidas: Set global de todas las URLs descubiertas hasta el momento.
            - pendientes: Set de URLs más profundas que el nivel actual, pendientes de
                          reclasificar cuando el nivel objetivo sea el correcto.
            - visitadas: Set de URLs a las que ya se ha hecho petición HTTP.
            - subdominios_encontrados: Set de subdominios detectados.
            - urls_truncadas: Lista de directorios registrados con /* por exceso de hijos.
            - grafo_enlaces: Lista de pares (source, target) para el visualizador.
            - conexiones_vistas: Set de pares (source, target) ya añadidos al grafo.
            - parametros_get: Diccionario de parámetros GET detectados en las URLs.
            - contenido_robots: Texto del robots.txt si existe, None si no.
            - ruta_robots: URL completa del robots.txt si existe, None si no.
            - datos_sitemap: Diccionario con 'sitemaps' y 'urls' extraídas de sitemaps.
            - rutas_sitemap: Lista de URLs de sitemaps encontrados.
            - urls_inicio: Set de URLs descubiertas durante la fase inicial.
            - nivel_actual: Nivel de directorio que se está procesando en la iteración.
            - urls_en_este_nivel: URLs clasificadas para el nivel_actual.
            - urls_no_visitadas: Subconjunto de urls_en_este_nivel que no se han visitado.
            - hijos_por_padre: Diccionario que agrupa las URLs del nivel por su padre.
            - padre: URL padre de un conjunto de URLs hijas.
            - hijos: Lista de URLs hijas bajo ese padre.
            - urls_a_visitar: Set final de URLs del nivel_actual que sí se visitarán.
            - url_truncada: Representación con /* del directorio truncado.
            - nuevos_pendientes: Set temporal de pendientes para el siguiente nivel.
            - respuesta_raiz: Respuesta HTTP de la petición a la URL raíz.
            - respuesta: Respuesta HTTP de cada petición durante la expansión.
            - nuevos_enlaces: Lista de enlaces extraídos de una página visitada.
            - profundidad_enlace: Profundidad de directorio de un enlace encontrado.
            - nivel_objetivo: Nivel al que se clasifican los nuevos enlaces encontrados.
            - padre_objetivo: URL padre al nivel objetivo para un enlace más profundo.
            - profundidad_p: Profundidad de una URL pendiente.
            - padre_p: URL padre al nivel objetivo para una URL pendiente.
            - todas_las_urls: Lista final ordenada de todas las URLs descubiertas.
            - urls_por_nivel_listas: Versión serializable de urls_por_nivel (listas).
            - profundidad_maxima_alcanzada: Mayor nivel de directorio encontrado.

        Retorna:
            Diccionario con urls, urls_por_nivel, urls_truncadas, link_graph,
            subdomains, robots_txt, sitemap, get_params y metadatos.
        """

        if rutas_excluidas is None:
            rutas_excluidas = []

        #Se parsea la URL de inicio para extraer el dominio base
        url_base_parseada = urlparse(url_inicio)
        dominio_base = url_base_parseada.netloc.replace('www.', '')

        #Estado del descubrimiento
        urls_por_nivel: Dict[int, Set[str]] = {}
        urls_conocidas: Set[str] = set()
        pendientes: Set[str] = set()
        visitadas: Set[str] = set()
        subdominios_encontrados: Set[str] = set()
        urls_truncadas: List[str] = []

        #Parámetros GET detectados
        parametros_get: Dict[str, List] = {}

        #Archivos encontrados
        archivos_encontrados: Set[str] = set()

        #Se marca la raíz como conocida y visitada
        urls_conocidas.add(url_inicio)
        visitadas.add(url_inicio)

        #Inicio del descubrimiento inicial desde la raíz
        logger.info(f"DISCOVERER | Fase 0: descubrimiento inicial desde {url_inicio}")

        #Set de URLs descubiertas en la fase de inicio
        urls_inicio: Set[str] = set()

        #Petición GET a la raíz para extraer los enlaces del HTML
        respuesta_raiz = self._realizar_peticion(url_inicio)
        if respuesta_raiz is not None and self._es_respuesta_html(respuesta_raiz):
            enlaces_raiz = self._extraer_enlaces(respuesta_raiz.text, url_inicio)
            for enlace in enlaces_raiz:
                urls_inicio.add(enlace)
            logger.debug(f"DISCOVERER | HTML raíz: {len(enlaces_raiz)} enlaces extraídos")
        else:
            logger.warning(f"DISCOVERER | No se pudo obtener HTML de la raíz: {url_inicio}")

        #Se obtiene el robots.txt para descubrir rutas y sitemaps
        contenido_robots = self._obtener_robots_txt(url_inicio)
        ruta_robots = None

        if contenido_robots:
            ruta_robots = f"{url_base_parseada.scheme}://{url_base_parseada.netloc}/robots.txt"
            logger.debug(f"DISCOVERER | robots.txt encontrado")

            #Se extraen las rutas del robots.txt
            for linea in contenido_robots.split('\n'):
                linea = linea.strip()

                if linea.lower().startswith('allow:') or linea.lower().startswith('disallow:'):
                    path_robot = linea.split(':', 1)[1].strip()

                    #Se ignoran las directivas vacías, la raíz y los wildcards solos
                    if not path_robot or path_robot == '/' or path_robot.startswith('*'):
                        continue
                    
                    path_robot = path_robot.rstrip('*').rstrip('$').strip()
                    if not path_robot:
                        continue

                    #Se construye la URL completa y se añade como candidata
                    url_robot = f"{url_base_parseada.scheme}://{url_base_parseada.netloc}{path_robot}"
                    urls_inicio.add(url_robot)

        #Se obtienen los sitemap
        datos_sitemap = self._descubrir_urls_sitemap(url_inicio, contenido_robots)
        rutas_sitemap = datos_sitemap.get('sitemaps', [])

        #Se añaden las URLs de los sitemaps al pool de candidatas
        for url_sitemap in datos_sitemap.get('urls', []):
            urls_inicio.add(url_sitemap)

        if rutas_sitemap:
            logger.debug(
                f"DISCOVERER | Sitemaps: {len(rutas_sitemap)} encontrados, "
                f"{len(datos_sitemap.get('urls', []))} URLs"
            )

        #Se inicializa el nivel 1 y se clasifican las URLs de la fase 0
        urls_por_nivel[1] = set()

        for url in urls_inicio:
            #Se verifica que la URL tiene esquema HTTP/HTTPS
            try:
                parseada = urlparse(url)
            except Exception:
                continue

            if parseada.scheme not in ('http', 'https'):
                continue

            dominio_url = parseada.netloc.replace('www.', '')

            #Se detectan subdominios y se guardan aparte
            if self._es_subdominio(url, dominio_base):
                subdominios_encontrados.add(dominio_url)
                continue

            #Se ignoran URLs de otros dominios
            if dominio_url != dominio_base:
                continue

            #Se extraen parámetros GET si los tiene y se usa la URL base sin query
            url_base_sin_query = f"{parseada.scheme}://{parseada.netloc}{parseada.path}"
            if parseada.query:
                params = parse_qs(parseada.query)
                for nombre_param, valores in params.items():
                    if nombre_param not in parametros_get:
                        parametros_get[nombre_param] = []
                    for valor in valores:
                        if len(parametros_get[nombre_param]) < 5:
                            parametros_get[nombre_param].append(
                                [valor, parseada.path or "/"]
                            )

            #Se usa la URL base (sin query) para deduplicación
            url = url_base_sin_query

            #Se ignoran URLs ya conocidas
            if url in urls_conocidas:
                continue

            #Se ignoran URLs con patrones de exclusión
            if self._debe_excluirse(url, rutas_excluidas):
                continue

            profundidad = self._obtener_profundidad_url(url)

            if profundidad == 0:
                continue

            elif profundidad == 1:
                if not self._es_url_directorio(url):
                    archivos_encontrados.add(url)
                    urls_conocidas.add(url)
                    continue

                urls_por_nivel[1].add(url)
                urls_conocidas.add(url)

            else:
                padre_nivel1 = self._obtener_padre_nivel(url, 1)

                if padre_nivel1 is not None:
                    if not self._debe_excluirse(padre_nivel1, rutas_excluidas):
                        if padre_nivel1 not in urls_conocidas:
                            urls_por_nivel[1].add(padre_nivel1)
                            urls_conocidas.add(padre_nivel1)

                #La URL completa se guarda como pendiente solo si parece directorio
                #Los archivos se registran pero no se expanden
                if self._es_url_directorio(url):
                    pendientes.add(url)
                else:
                    archivos_encontrados.add(url)
                    urls_conocidas.add(url)

        logger.info(
            f"DISCOVERER | Fase 0 completada: "
            f"{len(urls_por_nivel[1])} URLs de nivel 1 descubiertas"
        )


        for nivel_actual in range(1, profundidad_maxima + 1):

            if self._cancelado:
                logger.warning("DISCOVERER | Descubrimiento cancelado por el usuario (Ctrl+C)")
                break

            #Se obtienen las URLs del nivel actual que aún no han sido visitadas
            urls_en_este_nivel = urls_por_nivel.get(nivel_actual, set())
            urls_no_visitadas = urls_en_este_nivel - visitadas

            if not urls_no_visitadas:
                logger.info(f"DISCOVERER | Nivel {nivel_actual}: sin URLs pendientes, fin del descubrimiento")
                break

            logger.info(
                f"DISCOVERER | Nivel {nivel_actual}: "
                f"procesando {len(urls_no_visitadas)} URLs"
            )


            hijos_por_padre: Dict[str, List[str]] = {}

            for url in urls_no_visitadas:
                #El padre de las URLs de nivel 1 es siempre la URL raíz
                if nivel_actual == 1:
                    padre = url_inicio
                else:
                    padre = self._obtener_padre_nivel(url, nivel_actual - 1)
                    if padre is None:
                        padre = url_inicio

                if padre not in hijos_por_padre:
                    hijos_por_padre[padre] = []

                hijos_por_padre[padre].append(url)

            #Se determinan qué URLs se visitan y cuáles se truncan
            urls_a_visitar: Set[str] = set()

            #Se truncan las URLs con demasiados hijos
            for padre, hijos in hijos_por_padre.items():
                if len(hijos) > max_urls_directorio:
                    url_truncada = padre.rstrip('/') + '/*'
                    urls_truncadas.append(url_truncada)

                    #Se eliminan los hijos de urls_por_nivel para que no aparezcan en la lista final 
                    for hijo in hijos:
                        urls_por_nivel[nivel_actual].discard(hijo)
                        urls_conocidas.discard(hijo)

                    logger.warning(
                        f"DISCOVERER | Directorio truncado: {padre} "
                        f"tiene {len(hijos)} hijos (>{max_urls_directorio}). "
                        f"Registrado como {url_truncada}"
                    )
                else:
                    for hijo in hijos:
                        urls_a_visitar.add(hijo)

            #Se inicializa el siguiente nivel
            if nivel_actual < profundidad_maxima:
                if (nivel_actual + 1) not in urls_por_nivel:
                    urls_por_nivel[nivel_actual + 1] = set()


            #Se visitan las URLs del nivel actual
            paginas_procesadas = 0

            for url in urls_a_visitar:
                if self._cancelado:
                    break

                #Se marca la URL como visitada antes de la petición
                visitadas.add(url)
                paginas_procesadas = paginas_procesadas + 1

                #Si ya estamos en el nivel máximo, no hace falta visitar
                if nivel_actual >= profundidad_maxima:
                    continue

                respuesta = self._realizar_peticion(url)

                if respuesta is None:
                    continue

                if not self._es_respuesta_html(respuesta):
                    continue

                #Se extraen los enlaces del HTML de esta página
                nuevos_enlaces = self._extraer_enlaces(respuesta.text, url)

                nivel_objetivo = nivel_actual + 1

                for enlace in nuevos_enlaces:
                    if self._cancelado:
                        break

                    #Se valida el esquema HTTP/HTTPS
                    try:
                        parseada_enlace = urlparse(enlace)
                    except Exception:
                        continue

                    if parseada_enlace.scheme not in ('http', 'https'):
                        continue

                    dominio_enlace = parseada_enlace.netloc.replace('www.', '')

                    #Se detectan y guardan subdominios
                    if self._es_subdominio(enlace, dominio_base):
                        subdominios_encontrados.add(dominio_enlace)
                        continue

                    #Se ignoran URLs de otros dominios
                    if dominio_enlace != dominio_base:
                        continue

                    #Se extraen parámetros GET y se usa la URL base sin query
                    enlace_base = f"{parseada_enlace.scheme}://{parseada_enlace.netloc}{parseada_enlace.path}"
                    if parseada_enlace.query:
                        params = parse_qs(parseada_enlace.query)
                        for nombre_param, valores in params.items():
                            if nombre_param not in parametros_get:
                                parametros_get[nombre_param] = []
                            for valor in valores:
                                if len(parametros_get[nombre_param]) < 5:
                                    parametros_get[nombre_param].append(
                                        [valor, parseada_enlace.path or "/"]
                                    )

                    #Se usa la URL base para todas las comprobaciones
                    enlace = enlace_base

                    #Se ignoran URLs ya visitadas o ya conocidas
                    if enlace in visitadas:
                        continue

                    #Se ignoran URLs con patrones de exclusión
                    if self._debe_excluirse(enlace, rutas_excluidas):
                        continue

                    profundidad_enlace = self._obtener_profundidad_url(enlace)

                    if profundidad_enlace == nivel_objetivo:
                        #Los archivos se registran pero no se visitan
                        if not self._es_url_directorio(enlace):
                            if enlace not in urls_conocidas:
                                archivos_encontrados.add(enlace)
                                urls_conocidas.add(enlace)
                            continue

                        if enlace not in urls_conocidas:
                            urls_por_nivel[nivel_objetivo].add(enlace)
                            urls_conocidas.add(enlace)

                    elif profundidad_enlace > nivel_objetivo:
                        #Se extrae su padre en el nivel objetivo y se añade allí.
                        #La URL completa se guarda como pendiente para niveles futuros.
                        padre_objetivo = self._obtener_padre_nivel(enlace, nivel_objetivo)

                        if padre_objetivo is not None:
                            if not self._debe_excluirse(padre_objetivo, rutas_excluidas):
                                if padre_objetivo not in urls_conocidas:
                                    urls_por_nivel[nivel_objetivo].add(padre_objetivo)
                                    urls_conocidas.add(padre_objetivo)

                        #La URL completa queda pendiente solo si es directorio
                        #Los archivos se registran pero no se expanden
                        if self._es_url_directorio(enlace):
                            if enlace not in visitadas and enlace not in urls_conocidas:
                                pendientes.add(enlace)
                        else:
                            if enlace not in urls_conocidas:
                                archivos_encontrados.add(enlace)
                                urls_conocidas.add(enlace)

                #Se muestra el progreso de la fase actual
                logger.info(
                    f"DISCOVERER | [nivel={nivel_actual}] "
                    f"[{paginas_procesadas}/{len(urls_a_visitar)}] {url}"
                )

            #Se comprueba cuáles pertenecen al siguiente nivel objetivo.
            if nivel_actual < profundidad_maxima:
                nivel_objetivo = nivel_actual + 1
                nuevos_pendientes: Set[str] = set()

                for url_pendiente in pendientes:
                    if self._cancelado:
                        break

                    try:
                        parseada_p = urlparse(url_pendiente)
                    except Exception:
                        continue

                    dominio_p = parseada_p.netloc.replace('www.', '')

                    #Se ignoran URLs de otros dominios o subdominios en pendientes
                    if dominio_p != dominio_base:
                        continue

                    if url_pendiente in visitadas:
                        continue

                    if self._debe_excluirse(url_pendiente, rutas_excluidas):
                        continue

                    profundidad_p = self._obtener_profundidad_url(url_pendiente)

                    if profundidad_p == nivel_objetivo:
                        #Esta URL pendiente pertenece exactamente al siguiente nivel
                        if url_pendiente not in urls_conocidas:
                            urls_por_nivel[nivel_objetivo].add(url_pendiente)
                            urls_conocidas.add(url_pendiente)

                    elif profundidad_p > nivel_objetivo:
                        #Sigue siendo más profunda: se extrae el padre del siguiente nivel
                        padre_p = self._obtener_padre_nivel(url_pendiente, nivel_objetivo)

                        if padre_p is not None:
                            if not self._debe_excluirse(padre_p, rutas_excluidas):
                                if padre_p not in urls_conocidas:
                                    urls_por_nivel[nivel_objetivo].add(padre_p)
                                    urls_conocidas.add(padre_p)

                        #La URL completa sigue siendo pendiente para niveles futuros
                        nuevos_pendientes.add(url_pendiente)

                #Se actualiza el set de pendientes para la siguiente iteración
                pendientes = nuevos_pendientes

            logger.info(
                f"DISCOVERER | Nivel {nivel_actual} completado: "
                f"{paginas_procesadas} páginas visitadas"
            )

        #Se construye la lista ordenada de todas las URLs descubiertas
        todas_las_urls: List[str] = [url_inicio]
        urls_por_nivel_listas: Dict[str, List[str]] = {}

        for nivel in sorted(urls_por_nivel.keys()):
            lista_nivel = sorted(list(urls_por_nivel[nivel]))
            urls_por_nivel_listas[str(nivel)] = lista_nivel
            todas_las_urls.extend(lista_nivel)

        #Se añaden los archivos encontrados al final de la lista
        #Se agrupan por directorio padre y se aplica max_urls_directorio
        archivos_por_padre: Dict[str, List[str]] = {}
        for archivo in archivos_encontrados:
            parseada_archivo = urlparse(archivo)
            path_archivo = parseada_archivo.path or "/"
            directorio_padre = path_archivo[:path_archivo.rfind('/') + 1]
            padre_completo = f"{parseada_archivo.scheme}://{parseada_archivo.netloc}{directorio_padre}"

            if padre_completo not in archivos_por_padre:
                archivos_por_padre[padre_completo] = []
            archivos_por_padre[padre_completo].append(archivo)

        for padre, archivos_hijos in archivos_por_padre.items():
            if len(archivos_hijos) > max_urls_directorio:
                url_truncada = padre.rstrip('/') + '/*'
                if url_truncada not in urls_truncadas:
                    urls_truncadas.append(url_truncada)
                logger.warning(
                    f"DISCOVERER | Archivos truncados: {padre} "
                    f"tiene {len(archivos_hijos)} archivos (>{max_urls_directorio}). "
                    f"Registrado como {url_truncada}"
                )
            else:
                for archivo in sorted(archivos_hijos):
                    if archivo not in todas_las_urls:
                        todas_las_urls.append(archivo)

        #Se añaden los directorios truncados al final de la lista
        for url_truncada in urls_truncadas:
            if url_truncada not in todas_las_urls:
                todas_las_urls.append(url_truncada)

        #Se calcula la profundidad máxima efectivamente alcanzada
        if urls_por_nivel:
            profundidad_maxima_alcanzada = max(urls_por_nivel.keys())
        else:
            profundidad_maxima_alcanzada = 0

        if urls_truncadas:
            logger.warning(
                f"DISCOVERER | {len(urls_truncadas)} directorios truncados por exceso de URLs"
            )

        logger.success(
            f"DISCOVERER | Completado: {len(todas_las_urls)} URLs descubiertas, "
            f"profundidad máxima alcanzada: {profundidad_maxima_alcanzada}"
        )

        if subdominios_encontrados:
            logger.info(f"DISCOVERER | Subdominios detectados: {len(subdominios_encontrados)}")

        #Se construye el diccionario de resultados compatible con el visualizador
        resultado = {
            "urls": todas_las_urls,
            "urls_por_nivel": urls_por_nivel_listas,
            "urls_truncadas": urls_truncadas,
            "urls_discovered": len(todas_las_urls),
            "max_depth": profundidad_maxima_alcanzada,
            "exclude_paths": rutas_excluidas,
            "base_url": url_inicio,
            "subdomains": list(subdominios_encontrados),
            "robots_txt": ruta_robots,
            "sitemap": rutas_sitemap,
            "get_params": parametros_get,
        }

        return resultado
