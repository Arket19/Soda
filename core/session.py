"""
Este módulo gestiona sesiones HTTP asíncronas utilizando un patrón 'context manager' .

Funcionalidades:
    - Gestión  del ciclo de vida del cliente HTTP
    - Optimiza múltiples peticiones mediante connection pooling
    - Reintentos automáticos con backoff exponencial
    - Soporte para proxy
"""

import asyncio
import httpx

from loguru import logger

from typing import (
    Optional,
    Dict,
    Any,
)

from core import (
    TIMEOUT_POR_DEFECTO,
    MAX_REINTENTOS,
    BASE_BACKOFF,
    MAX_CONEXIONES,
    USER_AGENT_POR_DEFECTO,
)



class sesionHttpAsincrona:
    """
    Qué hace:
        Gestiona sesiones HTTP asíncronas con soporte para reintentos y pooling.
        Encapsula un cliente httpx.AsyncClient y proporciona métodos convenientes
        para realizar peticiones HTTP de forma robusta.
    """

    def __init__(
        self,
        timeout: float = TIMEOUT_POR_DEFECTO,
        max_reintentos: int = MAX_REINTENTOS,
        user_agent: str = USER_AGENT_POR_DEFECTO,
        verificar_ssl: bool = True,
        seguir_redirecciones: bool = True,
        proxy: Optional[str] = None,
    ) -> None:
        """
        Qué hace:
            Inicializa el gestor de sesiones con la configuración especificada.
            No se crea el cliente HTTP todavía, eso se hace al entrar en el context manager.

        Argumentos:
            - timeout: Tiempo máximo de espera en segundos para cada petición.
            - max_reintentos: Intentos máximos antes de considerar la petición fallida.
            - user_agent: Cadena User-Agent para identificar la herramienta.
            - verificar_ssl: Si debe verificar certificados SSL (False para proxies).
            - seguir_redirecciones: Si debe seguir redirecciones HTTP 301/302/etc.
            - proxy: URL del proxy por si se quiere interceptar o analizar el tráfico.

        Atributos de instancia creados:
            - self.timeout: Almacena el timeout configurado.
            - self.max_reintentos: Almacena el número máximo de reintentos.
            - self._user_agent: Almacena el User-Agent.
            - self._verificar_ssl: Almacena la configuración SSL.
            - self._seguir_redirecciones: Almacena configuración de redirecciones.
            - self._proxy: Almacena la URL del proxy.
            - self.cliente: Cliente HTTP asíncrono.
        """
        
        #Se almacenan los parámetros de configuración
        self.timeout = timeout
        self.max_reintentos = max_reintentos
        self._user_agent = user_agent
        self._verificar_ssl = verificar_ssl
        self._seguir_redirecciones = seguir_redirecciones
        self._proxy = proxy
        
        #El cliente se inicializa a None, se creará al entrar en el context manager (inicialización diferida o lazy loading)
        self.cliente = None
        
        #Se registra en el log la configuración con la que se inicializa
        logger.debug(
            f"SODA       | Sesion HTTP asincrona inicializada: timeout={timeout}s, "
            f"max_reintentos={max_reintentos}, verificar_ssl={verificar_ssl}, proxy={proxy}"
        )



    async def __aenter__(self) -> "sesionHttpAsincrona":
        """
        Qué hace:
            Método especial que se ejecuta al usar "async with".
            Crea el cliente HTTP asíncrono con la configuración definida.

        Variables:
            - limites_conexiones: Objeto httpx.Limits que define el pool de conexiones.
            - cabeceras: Diccionario con las cabeceras HTTP por defecto.
            - MAX_CONEXIONES: Número máximo de conexiones simultáneas
            - max_keepalive_connections: Conexiones que se mantienen abiertas entre peticiones

        Retorna:
            La instancia de sesionHttpAsincrona lista para usar.
        """
        
        #Se configuran los límites del pool de conexiones
        limites_conexiones = httpx.Limits(
            max_connections=MAX_CONEXIONES,
            max_keepalive_connections=MAX_CONEXIONES // 2,
        )
        
        #Se definen las cabeceras HTTP por defecto para que las peticiones parezcan de un navegador real
        cabeceras = {
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }
        
        #Se crea el cliente HTTP asíncrono con toda la configuración
        self.cliente = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            limits=limites_conexiones,
            headers=cabeceras,
            verify=self._verificar_ssl,
            follow_redirects=self._seguir_redirecciones,
            proxy=self._proxy,
        )
        
        logger.debug(f"SODA       | Cliente HTTP asíncrono creado")
        
        return self



    async def __aexit__(self,
        tipo_excepcion,
        valor_excepcion,
        traceback
    ) -> None:
        """
        Qué hace:
            Método especial que se ejecuta al salir del "async with".
            Cierra el cliente HTTP para liberar recursos de red.

        Argumentos:
            - tipo_excepcion: Tipo de excepción si ocurrió alguna.
            - valor_excepcion: Valor/mensaje de la excepción.
            - traceback: Traceback de la excepción para debugging.
        """
        
        #Se cierra el cliente solo si existe
        if self.cliente:
            logger.debug("SODA       | Cliente HTTP asíncrono cerrado")
            await self.cliente.aclose()



    async def get(
        self,
        url: str,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Realiza una petición HTTP GET con reintentos automáticos.

        Argumentos:
            - url: URL objetivo de la petición.
            - **kwargs: Argumentos adicionales opcionales para httpx

        Retorna:
            Objeto Response de httpx con la respuesta del servidor,
            o None si fallan todos los reintentos.
        """
        
        return await self._realizar_peticion("GET", url, **kwargs)



    async def head(
        self,
        url: str,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Realiza una petición HTTP HEAD (solo cabeceras, sin cuerpo).

        Argumentos:
            - url: URL objetivo de la petición.
            - **kwargs: Argumentos adicionales para httpx.

        Retorna:
            Objeto Response de httpx o None si fallan todos los reintentos.
        """
        
        return await self._realizar_peticion("HEAD", url, **kwargs)



    async def delete(
        self,
        url: str,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Realiza una petición HTTP DELETE con reintentos automáticos.

        Argumentos:
            - url: URL objetivo de la petición.
            - **kwargs: Argumentos adicionales opcionales para httpx.

        Retorna:
            Objeto Response de httpx con la respuesta del servidor,
            o None si fallan todos los reintentos.
        """
        
        return await self._realizar_peticion("DELETE", url, **kwargs)



    async def options(
        self,
        url: str,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Realiza una petición HTTP OPTIONS con reintentos automáticos.

        Argumentos:
            - url: URL objetivo de la petición.
            - **kwargs: Argumentos adicionales opcionales para httpx.

        Retorna:
            Objeto Response de httpx con la respuesta del servidor,
            o None si fallan todos los reintentos.
        """
        
        return await self._realizar_peticion("OPTIONS", url, **kwargs)



    async def post(
        self,
        url: str,
        datos: Optional[Dict] = None,
        json: Optional[Dict] = None,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Realiza una petición HTTP POST con reintentos automáticos.

        Argumentos:
            - url: URL objetivo de la petición.
            - datos: Datos para enviar como form-data (application/x-www-form-urlencoded).
            - json: Datos para enviar como JSON (application/json).
            - **kwargs: Argumentos adicionales para httpx.

        Retorna:
            Objeto Response de httpx o None si fallan todos los reintentos.
        """
        
        return await self._realizar_peticion("POST", url, data=datos, json=json, **kwargs)



    async def put(
        self,
        url: str,
        datos: Optional[Dict] = None,
        json: Optional[Dict] = None,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Realiza una petición HTTP PUT con reintentos automáticos.

        Argumentos:
            - url: URL objetivo de la petición.
            - datos: Datos para enviar como form-data.
            - json: Datos para enviar como JSON.
            - **kwargs: Argumentos adicionales opcionales para httpx.

        Retorna:
            Objeto Response de httpx con la respuesta del servidor,
            o None si fallan todos los reintentos.
        """
        
        return await self._realizar_peticion("PUT", url, data=datos, json=json, **kwargs)



    async def patch(
        self,
        url: str,
        datos: Optional[Dict] = None,
        json: Optional[Dict] = None,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Realiza una petición HTTP PATCH con reintentos automáticos.

        Argumentos:
            - url: URL objetivo de la petición.
            - datos: Datos para enviar como form-data.
            - json: Datos para enviar como JSON.
            - **kwargs: Argumentos adicionales opcionales para httpx.

        Retorna:
            Objeto Response de httpx con la respuesta del servidor,
            o None si fallan todos los reintentos.
        """
        
        return await self._realizar_peticion("PATCH", url, data=datos, json=json, **kwargs)



    async def _realizar_peticion(
        self,
        metodo: str,
        url: str,
        **kwargs: Any,
    ) -> Optional[httpx.Response]:
        """
        Qué hace:
            Método interno que realiza las peticiones HTTP con reintentos.

        Argumentos:
            - metodo: Método HTTP.
            - url: URL objetivo de la petición.
            - **kwargs: Argumentos adicionales para httpx.

        Variables:
            - excepcion: Guarda la última excepción para el log final.
            - intento: Número del intento actual (1, 2, 3...).
            - respuesta: Objeto Response si la petición tuvo éxito.
            - espera: Tiempo de espera antes del siguiente reintento.

        Retorna:
            Objeto Response o None si fallan todos los reintentos.
        """
        
        #Se verifica que el cliente esté inicializado
        if not self.cliente:
            raise ValueError(
                "El cliente aún no se ha inicializado."
            )
        
        #Se inicializa la variable que guardará la excepción en caso de error 
        excepcion: Optional[Exception] = None
        
        #Se intenta hacer la petición HTTP con reintentos y se manejan los errores
        for intento in range(1, self.max_reintentos + 1):
            try:
                respuesta = await self.cliente.request(metodo, url, **kwargs)
                
                #Se registra el código de estado de la respuesta en lo logs
                logger.debug(f"SODA       | {metodo} {url} -> {respuesta.status_code}")
                
                return respuesta

            #Se manejan los errores de timeout   
            except httpx.TimeoutException as error:
                excepcion = error
                logger.warning(f"SODA       | Timeout en {metodo} {url} (intento {intento}/{self.max_reintentos})")
            
            #Se manejan los errores de conexión
            except httpx.ConnectError as error:
                excepcion = error
                logger.warning(f"SODA       | Error de conexión en {url} (intento {intento}/{self.max_reintentos})")

            #Se manejan los errores inesperados
            except Exception as error:
                excepcion = error
                logger.error(f"SODA       | Error inesperado en {metodo} {url}: {error}")
            
            #Reintentos con backoff exponencial. Fórmula de backoff exponencial: Delay = Base × (Multiplier ^ AttemptNumber).
            if intento < self.max_reintentos:
                espera = BASE_BACKOFF * (2 ** (intento - 1))
                await asyncio.sleep(espera)
        
        #Han fallado todos los reintentos
        logger.error(f"SODA       | Fallaron todos los reintentos para {metodo} {url}: {excepcion}")
        
        return None
