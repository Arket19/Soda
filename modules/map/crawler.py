"""
Este módulo realiza crawling de una web para descubrir URLs, subdominios,
archivos robots.txt, sitemaps y parámetros GET.

Funcionalidades:
    - Crawleo recursivo por profundidad con límite configurable de URLs.
    - Suplantación de huellas TLS/JA3 mediante curl_cffi para evitar detección.
    - Rotación de User-Agents y throttling con jittering entre peticiones.
    - Obtención y parsing de robots.txt y sitemaps XML.
    - Extracción de enlaces HTML con BeautifulSoup (lxml como parser).
    - Detección de subdominios y parámetros GET inyectables.
    - Reintentos con backoff exponencial ante errores de conexión.
"""

import asyncio
import time
import random
import re

from collections import defaultdict
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
    MAX_URLS_CRAWLER,
    BASE_BACKOFF,
)
from core.session import sesionHttpAsincrona
from core.report_gen import GeneradorReportes



class Crawler:
    """
    Qué hace:
        Crawler web que descubre URLs de un sitio web navegando por sus enlaces
        recursivamente. Implementa múltiples técnicas anti-detección para
        evitar ser bloqueado por WAFs.

    Atributos específicos de la clase:
        - LISTA_USER_AGENTS: Lista de User-Agents de navegadores reales.
        - SUPLANTACIONES_NAVEGADOR: Navegadores a suplantar con curl_cffi.
        - EXTENSIONES_ESTATICAS: Extensiones de archivos estáticos a ignorar.
    """

    NOMBRE_MODULO: str = "crawler"
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
            Inicializa el crawler con la configuración especificada.

        Argumentos:
            - delay_base: Tiempo base entre peticiones (segundos).
            - rango_jitter: Rango (min, max) para aleatorizar el delay.
            - max_reintentos: Número máximo de reintentos por petición fallida.
            - timeout: Tiempo máximo de espera por petición (segundos).

        Atributos de instancia creados:
            - self.delay_base: Almacena el delay base.
            - self.rango_jitter: Almacena el rango de variación.
            - self.max_reintentos: Almacena el número de reintentos.
            - self.timeout: Almacena el timeout.
            - self.sesion: Sesión HTTP.
            - self.es_primera_peticion: Flag para no hacer throttling en la primera petición.
            - self.historial_referer: Lista de URLs para usar como Referer.
        """

        #Se configuran los intentos, el delay y el timeout
        self.delay_base = delay_base
        self.rango_jitter = rango_jitter
        self.max_reintentos = max_reintentos
        self.timeout = timeout

        #Se configura el estado inicial del crawler
        self.sesion: Optional[Session] = None
        self.es_primera_peticion: bool = True
        self.historial_referer: List[str] = []

        #Flag de cancelación para Ctrl+C.



    async def run(
        self,
        url: str,
        session: sesionHttpAsincrona,
        report: GeneradorReportes,
        profundidad_maxima: int = 2,
        rutas_excluidas: List[str] = None,
        max_urls: int = MAX_URLS_CRAWLER,
        incluir_robots: bool = False,
        incluir_sitemaps: bool = False,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Método principal que ejecuta el crawler de forma asíncrona.

        Argumentos:
            - url: URL objetivo desde donde comenzar el crawleo.
            - session: Sesión HTTP asíncrona (no se usa, pero se mantiene para
                       compatibilidad con la arquitectura de SODA).
            - report: Generador de reportes donde se guardan los hallazgos.
            - profundidad_maxima: Profundidad máxima de navegación.
            - rutas_excluidas: Lista de rutas a excluir del crawleo.
            - max_urls: Límite máximo de URLs a descubrir.

        Variables:
            - event_loop: El event loop de asyncio que gestiona las operaciones async.
            - resultados: Diccionario con los resultados del crawleo.

        Retorna:
            Diccionario con los resultados del crawleo.
        """

        logger.info(f"CRAWLER    | Iniciando crawleo de {url}")
        logger.info(f"CRAWLER    | Profundidad máxima: {profundidad_maxima}, Límite URLs: {max_urls}")

        #Se reinicia el flag de cancelación para esta ejecución
        self._cancelado = False

        #Se obtiene el event loop en ejecución
        event_loop = asyncio.get_running_loop()

        #Se ejecuta el crawling síncrono en un thread de run_in_executor()
        try:
            resultados = await event_loop.run_in_executor(
                None,
                self._ejecutar_crawling_sincrono,
                url,
                profundidad_maxima,
                rutas_excluidas,
                max_urls,
                incluir_robots,
                incluir_sitemaps,
            )
        except (KeyboardInterrupt, asyncio.CancelledError):
            self._cancelado = True
            logger.warning("CRAWLER    | Cancelando crawleo...")
            await asyncio.sleep(1)
            raise

        #Se añaden los hallazgos al reporte
        report.añadir_hallazgo(
            nombre_modulo=self.NOMBRE_MODULO,
            categoria=self.CATEGORIA,
            datos=resultados,
        )

        logger.info(f"CRAWLER    | Crawleo completado. URLs descubiertas: {len(resultados.get('urls', []))}")

        return resultados



    def _ejecutar_crawling_sincrono(
        self,
        url_inicio: str,
        profundidad_maxima: int,
        rutas_excluidas: List[str],
        max_urls: int,
        incluir_robots: bool = False,
        incluir_sitemaps: bool = False,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Wrapper síncrono que ejecuta el método descubrir_urls().

        Argumentos:
            - url_inicio: URL inicial desde donde comenzar.
            - profundidad_maxima: Profundidad máxima de navegación.
            - rutas_excluidas: Lista de rutas a excluir.
            - max_urls: Límite máximo de URLs a descubrir.

        Retorna:
            Diccionario con los resultados del crawleo.
        """

        try:
            #Se reinicia el estado interno para esta ejecución
            self.es_primera_peticion = True
            self.historial_referer = []
            
            #Se inicializa la sesión HTTP en el mismo thread donde se usará
            self._inicializar_sesion_HTTP_sincrona()

            #Se ejecuta el crawling
            resultados = self._descubrir_urls(
                url_inicio=url_inicio,
                profundidad_maxima=profundidad_maxima,
                rutas_excluidas=rutas_excluidas,
                max_urls=max_urls,
                incluir_robots=incluir_robots,
                incluir_sitemaps=incluir_sitemaps,
            )
            return resultados

        except Exception as error:
            logger.error(f"CRAWLER    | Error durante el crawleo: {error}")
            return {
                "urls": [],
                "urls_discovered": 0,
                "max_depth": 0,
                "exclude_paths": [],
                "base_url": url_inicio,
                "link_graph": [],
                "subdomains": [],
                "robots_txt": None,
                "sitemap": [],
                "get_params": {},
                "error": str(error),
            }

        finally:
            self._cerrar_sesion()



    def _cerrar_sesion(self) -> None:
        """
        Qué hace:
            Cierra la sesión HTTP y libera los recursos de red.
        """

        if self.sesion is not None:
            self.sesion.close()
            self.sesion = None
            logger.debug("CRAWLER    | Sesión HTTP del crawler cerrada")



    def _inicializar_sesion_HTTP_sincrona(self) -> None:
        """
        Qué hace:
            Inicializa una nueva sesión HTTP simulando un navegador real.

        Variables:
            - navegador: Navegador seleccionado aleatoriamente para suplantación.
        """

        #Se selecciona un navegador aleatorio para suplantar
        navegador = random.choice(self.SUPLANTACIONES_NAVEGADOR)
        self.sesion = Session(impersonate=navegador)

        #Se configuran los headers HTTP para simular un navegador real
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
            Calcula el tiempo de espera con variación aleatoria (jittering).

        Variables:
            - jitter: Variación aleatoria dentro del rango configurado.
            - delay: Delay final (base + jitter).

        Retorna:
            Tiempo de espera en segundos.
        """

        jitter = random.uniform(self.rango_jitter[0], self.rango_jitter[1])
        delay = self.delay_base + jitter

        return delay



    def _esperar(self) -> None:
        """
        Qué hace:
            Espera un tiempo aleatorio entre peticiones (throttling).

        Variables:
            - delay: Tiempo total a esperar (segundos).
            - transcurrido: Tiempo ya transcurrido (segundos).
            - incremento: Fragmento de espera por iteración (segundos).
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
            Obtiene un referer realista para la petición, simulando
            que el usuario ha navegado desde otra página del mismo dominio.

        Argumentos:
            - url_actual: URL que se va a visitar.

        Variables:
            - url_parseada: Componentes de la URL actual.
            - referer: URL que se usará como referer.

        Retorna:
            URL del referer.
        """

        #Si hay historial, se usa la última URL visitada
        if self.historial_referer:
            referer = self.historial_referer[-1]
        
        #Si no hay historial, se usa la página principal del sitio
        else:
            url_parseada = urlparse(url_actual)
            referer = f"{url_parseada.scheme}://{url_parseada.netloc}/"

        return referer



    def _es_respuesta_html(self, respuesta: requests.Response) -> bool:
        """
        Qué hace:
            Verifica si la respuesta HTTP contiene HTML válido.

        Argumentos:
            - respuesta: Objeto Response de la petición.

        Variables:
            - content_type: Valor del header Content-Type.

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
            y reintentos con backoff exponencial.

        Argumentos:
            - url: URL a visitar.
            - metodo: Método HTTP (GET, POST, etc.).
            - **kwargs: Argumentos adicionales para la petición.

        Variables:
            - user_agent: UA aleatorio para esta petición.
            - referer: URL de origen simulada.
            - headers: Diccionario de cabeceras HTTP.
            - respuesta: Objeto Response de la petición.
            - intento: Número de intento actual.
            - espera: Tiempo de espera entre reintentos.
            - status: Código de estado HTTP de la respuesta.

        Retorna:
            Objeto Response o None si falla.
        """

        #Se ejecuta el throttling, exceptuando en la primera iteracion
        if not self.es_primera_peticion:
            self._esperar()
        self.es_primera_peticion = False

        #Se selecciona un User-Agent aleatorio
        user_agent = random.choice(self.LISTA_USER_AGENTS)

        #Se obtiene un referer realista
        referer = self._obtener_referer(url)

        #Se configuran los headers para esta petición
        headers = kwargs.pop('headers', {})
        headers['User-Agent'] = user_agent
        headers['Referer'] = referer

        logger.debug(f"CRAWLER    | Fetching: {url}")
        logger.debug(f"CRAWLER    | User-Agent: {user_agent}")

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

                logger.debug(f"CRAWLER    | Código de estado {respuesta.status_code}: {url}")

                #Se actualiza el historial de referer
                self.historial_referer.append(url)

                #Se mantienen solo las últimas 10 URLs en historial
                if len(self.historial_referer) > 10:
                    self.historial_referer.pop(0)

                return respuesta

            except Exception as error:
                #Si hay un error 4xx, no se reintenta
                if respuesta is not None:
                    if hasattr(respuesta, 'status_code'):
                        status = respuesta.status_code
                        if status >= 400 and status < 500:
                            logger.debug(f"CRAWLER    | Error HTTP {status}: {url}")
                            return None

                logger.warning(f"CRAWLER    | Intento {intento + 1}/{self.max_reintentos} falló: {error}")

                #Si quedan reintentos se hace backof
                if intento < self.max_reintentos - 1:
                    espera = BASE_BACKOFF * (2 ** intento)
                    logger.debug(f"CRAWLER    | Reintentando en {espera}s...")
                    time.sleep(espera)
                else:
                    logger.error(f"CRAWLER    | Falló después de {self.max_reintentos} intentos: {url}")

        return None



    def _extraer_enlaces(
        self,
        html: str,
        url_base: str,
        solo_mismo_dominio: bool = True,
    ) -> List[str]:
        """
        Qué hace:
            Extrae todos los enlaces válidos de una página HTML.

        Argumentos:
            - html: Contenido HTML de la página.
            - url_base: URL base para resolver enlaces relativos.
            - solo_mismo_dominio: Si True, solo retorna enlaces del mismo dominio.

        Variables:
            - enlaces: Lista de enlaces encontrados.
            - url_base_parseada: Componentes de la URL base.
            - dominio_base: Dominio extraído de la URL base.
            - soup: Objeto BeautifulSoup para parsear HTML.
            - etiqueta: Cada elemento HTML con atributo href.
            - href: Valor del atributo href.
            - url_absoluta: URL convertida a absoluta.
            - url_parseada: Componentes de la URL encontrada.
            - dominio_enlace: Dominio del enlace encontrado.
            - path_minusculas: Path en minúsculas para comparación.
            - es_archivo_estatico: Flag para saber si es archivo estático.
            - extension: Cada extensión estática a comprobar.
            - url_limpia: URL normalizada sin fragmentos.
            - vistos: Set para eliminar duplicados.
            - enlaces_unicos: Lista final sin duplicados.

        Retorna:
            Lista de URLs únicas encontradas.
        """

        enlaces = []
        url_base_parseada = urlparse(url_base)
        dominio_base = url_base_parseada.netloc.replace('www.', '')

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

            #Se filtra por mismo dominio si está activado
            dominio_enlace = url_parseada.netloc.replace('www.', '')
            if solo_mismo_dominio and dominio_enlace != dominio_base:
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
            - robots_url: URL del archivo robots.txt.
            - respuesta: Respuesta HTTP.

        Retorna:
            Contenido del robots.txt o None si no existe.
        """

        url_parseada = urlparse(url_base)
        robots_url = f"{url_parseada.scheme}://{url_parseada.netloc}/robots.txt"

        try:
            respuesta = self._realizar_peticion(robots_url)
            if respuesta is not None and respuesta.status_code == 200:
                return respuesta.text
            return None
        except Exception as error:
            logger.debug(f"CRAWLER    | Error obteniendo robots.txt: {error}")
            return None



    def _extraer_sitemaps_de_robots(self, contenido_robots: str) -> List[str]:
        """
        Qué hace:
            Busca URLs de sitemaps en el contenido de robots.txt.

        Argumentos:
            - contenido_robots: Contenido del archivo robots.txt.

        Variables:
            - sitemaps: Lista de URLs de sitemaps encontradas.
            - linea: Cada línea del robots.txt.
            - sitemap_url: URL extraída de la línea Sitemap:.

        Retorna:
            Lista de URLs de sitemaps encontradas.
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
            Obtiene el contenido de un archivo sitemap.

        Argumentos:
            - sitemap_url: URL del sitemap.

        Variables:
            - respuesta: Respuesta HTTP.

        Retorna:
            Contenido del sitemap o None si falla.
        """

        logger.debug(f"CRAWLER    | Obteniendo sitemap: {sitemap_url}")

        try:
            respuesta = self._realizar_peticion(sitemap_url)
            if respuesta is not None and respuesta.status_code == 200:
                return respuesta.text
            return None
        except Exception as error:
            logger.debug(f"CRAWLER    | Error obteniendo sitemap: {error}")
            return None



    def _parsear_urls_sitemap(self, contenido_sitemap: str) -> List[str]:
        """
        Qué hace:
            Extrae URLs de un sitemap XML usando expresiones regulares.

        Argumentos:
            - contenido_sitemap: Contenido XML del sitemap.

        Variables:
            - urls_sitemap: Lista de URLs extraídas.
            - patron_loc: Expresión regular para encontrar tags <loc>.
            - coincidencias: URLs encontradas por el regex.
            - url: Cada URL encontrada.

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

        Argumentos:
            - url_base: URL base del sitio.
            - contenido_robots: Contenido del robots.txt (opcional).

        Variables:
            - resultado: Diccionario con los datos descubiertos.
            - sitemap_urls: Lista de URLs de sitemaps a explorar.
            - url_parseada: Componentes de la URL base.
            - sitemaps_comunes: Ubicaciones típicas de sitemaps.
            - todas_las_urls: Lista acumulada de URLs encontradas.
            - sitemap_url: Cada sitemap a procesar.
            - contenido_sitemap: Contenido XML del sitemap.
            - urls: URLs extraídas de un sitemap.

        Retorna:
            Diccionario con 'sitemaps' (lista de sitemaps) y 'urls' (lista de URLs).
        """

        resultado = {
            'sitemaps': [],
            'urls': []
        }

        #Se usa contenido_robots si se proporciona, si no, se obtiene
        if contenido_robots is None:
            contenido_robots = self._obtener_robots_txt(url_base)

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
            - dominio_base: Dominio base para comparar.

        Variables:
            - parseada: Componentes de la URL.
            - dominio_url: Dominio extraído de la URL.

        Retorna:
            True si es un subdominio, False si es el mismo dominio o diferente.
        """

        parseada = urlparse(url)
        dominio_url = parseada.netloc.replace('www.', '')

        #Si es exactamente el mismo dominio, no es subdominio
        if dominio_url == dominio_base:
            return False

        #Se comprueba si termina con el dominio base 
        return dominio_url.endswith('.' + dominio_base)



    def _debe_excluirse(
        self,
        url: str,
        rutas_excluidas: List[str],
        path_base: str,
        dominio_base: str,
    ) -> bool:
        """
        Qué hace:
            Verifica si una URL debe ser excluida del crawleo.

        Argumentos:
            - url: URL a verificar.
            - rutas_excluidas: Lista de textos que si aparecen en la URL, se excluye.
            - path_base: Path de la URL inicial para limitar el crawleo.
            - dominio_base: Dominio base.

        Variables:
            - parseada: Componentes de la URL.
            - path_minusculas: Path en minúsculas para comparación.
            - excluido: Cada texto a buscar en la URL.
            - path_url: Path de la URL sin barra final.
            - dominio_url: Dominio de la URL.

        Retorna:
            True si la URL debe excluirse, False si debe procesarse.
        """

        parseada = urlparse(url)
        path_minusculas = parseada.path.lower()

        #Se comprueba si la URL contiene algún texto de exclusión
        for excluido in rutas_excluidas:
            if excluido.lower() in path_minusculas:
                return True

        #Se verifica que la URL esté dentro del path base
        path_url = parseada.path.rstrip('/')
        dominio_url = parseada.netloc.replace('www.', '')

        if dominio_url == dominio_base:
            if not path_url.startswith(path_base):
                return True

        return False



    def _descubrir_urls(
        self,
        url_inicio: str,
        profundidad_maxima: int = 2,
        rutas_excluidas: List[str] = None,
        max_urls: int = MAX_URLS_CRAWLER,
        incluir_robots: bool = False,
        incluir_sitemaps: bool = False,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Descubre URLs del sitio navegando recursivamente desde una URL inicial.
            Es el método principal del crawler que realiza el trabajo síncrono.

        Argumentos:
            - url_inicio: URL inicial desde donde comenzar.
            - profundidad_maxima: Profundidad máxima de navegación.
            - rutas_excluidas: Lista de textos a excluir de las URLs.
            - max_urls: Límite máximo de URLs a descubrir.

        Variables:
            - url_base_parseada: Componentes de la URL inicial.
            - path_base: Path de la URL inicial.
            - dominio_base: Dominio de la URL inicial.
            - urls_descubiertas: Diccionario {url: profundidad}.
            - subdominios_encontrados: Set de subdominios detectados.
            - por_crawlear: Cola de URLs pendientes [(url, profundidad)].
            - visitadas: Set de URLs ya procesadas.
            - parametros_get: Diccionario de parámetros GET detectados.
            - contenido_robots: Contenido del robots.txt.
            - datos_sitemap: Datos de los sitemaps.
            - ruta_robots: URL del robots.txt si existe.
            - rutas_sitemap: Lista de URLs de sitemaps encontrados.
            - paginas_exploradas: Contador de páginas procesadas.
            - interrumpido: Flag si el usuario canceló con Ctrl+C.
            - limite_alcanzado: Flag si se alcanzó el límite de URLs.

        Retorna:
            Diccionario con urls, base_url, link_graph, subdomains, etc.
            Todos los valores son serializables a JSON.
        """

        if rutas_excluidas is None:
            rutas_excluidas = []

        #Se parsea la URL base para extraer dominio y path
        url_base_parseada = urlparse(url_inicio)
        path_base = url_base_parseada.path.rstrip('/')
        dominio_base = url_base_parseada.netloc.replace('www.', '')

        #Estado del descubrimiento
        urls_descubiertas: Dict[str, int] = {url_inicio: 0}
        subdominios_encontrados: Set[str] = set()
        por_crawlear = [(url_inicio, 0)]
        visitadas: Set[str] = set()

        #Tracking de parámetros GET
        parametros_get: Dict[str, Set[tuple]] = defaultdict(set)


        logger.info(f"CRAWLER    | Iniciando crawleo desde: {url_inicio}")
        
        #Se obtienen el robots.txt y los sitemaps antes de empezar
        contenido_robots = self._obtener_robots_txt(url_inicio)
        datos_sitemap = self._descubrir_urls_sitemap(url_inicio, contenido_robots=contenido_robots)

        #Se guardan las rutas de los recursos encontrados
        url_parseada_base = urlparse(url_inicio)
        if contenido_robots:
            ruta_robots = f"{url_parseada_base.scheme}://{url_parseada_base.netloc}/robots.txt"
        else:
            ruta_robots = None

        rutas_sitemap = []
        if datos_sitemap and datos_sitemap["sitemaps"]:
            rutas_sitemap = datos_sitemap["sitemaps"]

        #Se meten URLs de robots.txt como rutas de profundidad 1 si el usuario lo solicita.
        if incluir_robots and contenido_robots:
            for linea in contenido_robots.split('\n'):
                linea = linea.strip()
                if linea.lower().startswith('allow:') or linea.lower().startswith('disallow:'):
                    path_robot = linea.split(':', 1)[1].strip()
                    if path_robot and path_robot != '/' and not path_robot.startswith('*'):
                        #Se elimina el wildcard del final si existe (ej: /admin/*)
                        path_robot = path_robot.rstrip('*')
                        url_robot = f"{url_parseada_base.scheme}://{url_parseada_base.netloc}{path_robot}"
                        if url_robot not in urls_descubiertas:
                            urls_descubiertas[url_robot] = 1
                            por_crawlear.append((url_robot, 1))
            logger.info(f"CRAWLER    | URLs de robots.txt añadidas a la cola de crawleo")

        #Se meten URLs de sitemaps como rutas de profundidad 1 si el usuario lo solicita.
        if incluir_sitemaps and datos_sitemap and datos_sitemap["urls"]:
            for url_sitemap in datos_sitemap["urls"]:
                if url_sitemap not in urls_descubiertas:
                    urls_descubiertas[url_sitemap] = 1
                    por_crawlear.append((url_sitemap, 1))
            logger.info(f"CRAWLER    | {len(datos_sitemap['urls'])} URLs de sitemaps añadidas a la cola de crawleo")

        #Contadores y flags de estado
        paginas_exploradas = 0
        interrumpido = False
        limite_alcanzado = False

        #Se verifica si el usuario canceló con Ctrl+C
        while por_crawlear:
            if self._cancelado:
                interrumpido = True
                logger.warning("CRAWLER    | Crawleo cancelado por el usuario (Ctrl+C)")
                logger.warning(f"CRAWLER    | Guardando {len(urls_descubiertas)} URLs descubiertas...")
                break

            #Se verifica si se ha alcanzado el numero maximo de urls
            if len(urls_descubiertas) >= max_urls:
                logger.warning(f"CRAWLER    | Límite de URLs alcanzado ({max_urls})")
                logger.warning("CRAWLER    | Recomendaciones:")
                logger.warning("CRAWLER    |   - Usa -E para excluir directorios grandes")
                logger.warning("CRAWLER    |   - Mapea secciones específicas")
                logger.warning("CRAWLER    |   - Reduce la profundidad con -D")
                limite_alcanzado = True
                break

            #Se saca una URL de la cola
            url, profundidad = por_crawlear.pop(0)

            #Se salta si ya fue visitada o debe excluirse
            if url in visitadas:
                continue
            if self._debe_excluirse(url, rutas_excluidas, path_base, dominio_base):
                continue

            #Se realiza la petición HTTP
            respuesta = self._realizar_peticion(url)

            visitadas.add(url)
            paginas_exploradas = paginas_exploradas + 1

            #Solo se procesan los enlaces si hay respuesta válida
            if respuesta is None:
                continue

            #No se procesan más enlaces si se alcanzó la profundidad máxima
            if profundidad >= profundidad_maxima:
                continue

            #Se valida que la respuesta sea HTML antes de parsear
            if not self._es_respuesta_html(respuesta):
                logger.debug(f"CRAWLER    | Saltando (no HTML): {url}")
                continue

            #Se extraen los enlaces del HTML (incluyendo subdominios)
            html = respuesta.text
            nuevos_enlaces = self._extraer_enlaces(html, url, solo_mismo_dominio=False)

            #Se procesan los enlaces encontrados
            for enlace in nuevos_enlaces:

                #Se detectan subdominios
                if self._es_subdominio(enlace, dominio_base):
                    subdominio = urlparse(enlace).netloc.replace('www.', '')
                    subdominios_encontrados.add(subdominio)
                    continue

                #Se verifica que sea del mismo dominio
                dominio_enlace = urlparse(enlace).netloc.replace('www.', '')
                if dominio_enlace != dominio_base:
                    continue

                #Se separa la URL sin query string para evitar duplicados por parámetros GET
                enlace_parseado = urlparse(enlace)
                enlace_sin_query = f"{enlace_parseado.scheme}://{enlace_parseado.netloc}{enlace_parseado.path}"

                #Se extraen parámetros GET antes de comprobar duplicados
                if enlace_parseado.query:
                    path_url = enlace_parseado.path or "/"
                    params = parse_qs(enlace_parseado.query)
                    for nombre_param in params:
                        valores = params[nombre_param]
                        for valor in valores:
                            #Se limita a 5 valores por parámetro
                            if len(parametros_get[nombre_param]) < 5:
                                parametros_get[nombre_param].add((valor, path_url))

                #Se añade solo si es nuevo y no debe excluirse
                ya_descubierto = enlace_sin_query in urls_descubiertas
                debe_excluir = self._debe_excluirse(enlace_sin_query, rutas_excluidas, path_base, dominio_base)

                if not ya_descubierto and not debe_excluir:
                    urls_descubiertas[enlace_sin_query] = profundidad + 1
                    por_crawlear.append((enlace_sin_query, profundidad + 1))


            #Se muestra el progreso
            pendientes = len(por_crawlear)
            delay_promedio = self.delay_base + sum(self.rango_jitter) / 2
            segundos_estimados = pendientes * delay_promedio

            if segundos_estimados < 60:
                tiempo_str = f"{segundos_estimados:.0f}s"
            else:
                tiempo_str = f"{segundos_estimados/60:.1f}m"

            logger.info(f"CRAWLER    | [{paginas_exploradas}] depth={profundidad}, pending={pendientes}, est={tiempo_str}")

        #Se ordenan las URLs por profundidad y alfabéticamente
        def criterio_orden(elemento):
            url_elemento = elemento[0]
            profundidad_elemento = elemento[1]
            return (profundidad_elemento, url_elemento)

        urls_ordenadas = sorted(urls_descubiertas.items(), key=criterio_orden)

        #Se loguea el resumen del crawleo
        if interrumpido:
            logger.warning(f"CRAWLER    | INTERRUMPIDO: {len(urls_descubiertas)} URLs guardadas")
        elif limite_alcanzado:
            logger.warning(f"CRAWLER    | PARCIAL: {len(urls_descubiertas)} URLs (límite alcanzado)")
        else:
            logger.success(f"CRAWLER    | Completado: {len(urls_descubiertas)} URLs descubiertas")

        logger.info(f"CRAWLER    | Páginas exploradas: {paginas_exploradas}")
        if subdominios_encontrados:
            logger.info(f"CRAWLER    | Subdominios detectados: {len(subdominios_encontrados)}")

        #Se construye el diccionario de resultados (serializable a JSON)
        lista_urls = []
        for url, profundidad in urls_ordenadas:
            lista_urls.append(url)

        #Se calcula la profundidad máxima alcanzada durante el crawleo
        profundidad_maxima_alcanzada = max(urls_descubiertas.values()) if urls_descubiertas else 0

        #Se convierten los sets a listas para serialización JSON
        resultado = {
            "urls": lista_urls,
            "urls_discovered": len(lista_urls),
            "max_depth": profundidad_maxima_alcanzada,
            "exclude_paths": rutas_excluidas,
            "base_url": url_inicio,
            "subdomains": list(subdominios_encontrados),
            "robots_txt": ruta_robots,
            "sitemap": rutas_sitemap,
            "get_params": {},
        }

        #Se convierten los sets de parámetros GET a listas
        for nombre_param in parametros_get:
            resultado["get_params"][nombre_param] = list(parametros_get[nombre_param])

        return resultado