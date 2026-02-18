"""
Este módulo realiza consultas DNS y WHOIS sobre el dominio objetivo.

Funcionalidades:
    - Resolución de registros DNS utilizando dnspython.
    - Consulta WHOIS del dominio utilizando python-whois. Se ejecuta en un executor para no bloquear el event loop.
    - Identificación de subdominios en registros DNS.
"""

import asyncio
import re
import dns.resolver
import dns.exception
import whois

from core.session import sesionHttpAsincrona
from core.report_gen import GeneradorReportes
from loguru import logger
from typing import Dict, List, Any
from urllib.parse import urlparse
from core import TIPOS_REGISTROS_DNS



class DNSRecon:
    """
    Qué hace:
        Esta clase realiza el reconocimiento DNS y WHOIS de un dominio.
        Es un módulo "pasivo" porque no interactúa de manera directa con el objetivo.
    
    Atributos específicos de la clase:
        - TIPOS_REGISTROS_DNS: Lista de los tipos de registros DNS que se consultanm.
    """
    
    NOMBRE_MODULO: str = "dns_whois"
    CATEGORIA: str = "passive"


    TIPOS_REGISTROS_DNS = TIPOS_REGISTROS_DNS


    def __init__(self, timeout: float = 5.0) -> None:
        """
        Qué hace:
            Inicializa el módulo y configura el resolver DNS que usaremos para las consultas.
        
        Argumentos:
            - timeout: Tiempo máximo en segundos que esperamos por cada consulta DNS antes de considerarla fallida.

        Atributos de instancia creados:
            - self.timeout: Tiempo máximo en segundos que esperamos por cada consulta DNS antes de considerarla fallida.
            - self.resolver: Objeto de dnspython que realiza las consultas DNS.
        """

        #Se crea y configura el resolver DNS
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    


    async def run(
        self,
        url: str,
        session: sesionHttpAsincrona,
        report: GeneradorReportes,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Ejecuta el reconocimiento DNS y WHOIS del dominio.
        
        Argumentos:
            url: URL objetivo.
            session: Sesión HTTP asíncrona (no se usa, pero se mantiene para que soda.py llame a todos los módulos de la misma manera).
            report: Reporte en el que se reflejan los hallazgos.

        Variables:
            - host: El dominio o IP extraído de la URL.
            - resultados: Diccionario con los hallazgos.
            - resultados_dns: Hallazgos DNS.
            - resultados_whois: Hallazgos WHOIS.

        Retorna:
            Diccionario con los resultados del reconocimiento DNS y WHOIS.
        """

        #Se extrae el host (dominio o IP) de la URL
        host = self._extraer_host(url)
        
        #Si el host es una IP, se salta el módulo
        if self._es_direccion_ip(host):
            logger.warning(f"DNS_WHOIS  | La URL especificada no contiene un dominio válido. No se realizará el reconocimiento DNS y WHOIS.")
            return {
                "host": host,
                "es_ip": True,
                "mensaje": "Módulo omitido: DNS y WHOIS solo aplican a dominios, no a direcciones IP.",
            }
        
        logger.info(f"DNS_WHOIS  | Iniciando reconocimiento DNS y WHOIS...")

        #Se crea un diccionario para almacenar todos los resultados
        resultados: Dict[str, Any] = {
            "host": host,
            "hallazgos_dns": {},
            "hallazgos_whois": {},
            "errores": [],
        }

        #Se consultan los registros DNS
        resultados_dns = await self._consultar_registros_dns(host)
        resultados["hallazgos_dns"] = resultados_dns
        
        #Se consulta la información WHOIS
        resultados_whois = await self._consultar_whois(host)
        resultados["hallazgos_whois"] = resultados_whois
        
        #Se agregan los hallazgos al reporte
        report.añadir_hallazgo(
            nombre_modulo=self.NOMBRE_MODULO,
            categoria=self.CATEGORIA,
            datos=resultados,
        )
        
        logger.info(f"DNS_WHOIS  | Reconocimiento DNS y WHOIS completado.")
        return resultados



    def _extraer_host(self, url: str) -> str:
        """
        Qué hace:
            Extrae el host (dominio o IP) de una URL, sin el puerto.
        
        Argumentos:
            url: URL objetivo del usuario.
        
        Variables:
            - url_parseada: Objeto con los componentes de la URL parseada.
            - netloc: La parte de la URL que contiene host y puerto.
            - host: El netloc sin el puerto.
        
        Retorna:
            Host extraído (dominio o IP, sin protocolo, puerto ni path).
        """
        
        #Se parsea la URL y se extrae el netloc
        url_parseada = urlparse(url)
        netloc = url_parseada.netloc
        
        #Se elimina el puerto si existe (ejemplo: "dominio.com:8080" -> "dominio.com")
        if ":" in netloc:
            host = netloc.split(":")[0]
        else:
            host = netloc
        
        return host



    def _es_direccion_ip(self, host: str) -> bool:
        """
        Qué hace:
            Verifica si un host es una dirección IP a través de una expresión regular.
        
        Argumentos:
            host: El host a verificar (ejemplo: "dominio.com" o "192.168.1.1").
        
        Variables:
            - patron_ipv4: Expresión regular para detectar direcciones IPv4.
            - patron_ipv6: Expresión regular simplificada para detectar direcciones IPv6.
        
        Retorna:
            True si es una IP, False si es un dominio.
        """
        
        #Patrones para IPv4 y IPv6
        patron_ipv4 = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        patron_ipv6 = r"^[0-9a-fA-F:]+$"
        
        #Se comprueba si coincide con alguno de los patrones
        if re.match(patron_ipv4, host) or re.match(patron_ipv6, host):
            return True
        
        return False



    def _resolver_dns_sincrono(self, dominio: str, tipo_registro: str) -> Any:
        """
        Qué hace:
            Realiza una consulta DNS de forma síncrona.
        
        Argumentos:
            - dominio: El dominio a consultar (ejemplo: "dominio.com").
            - tipo_registro: Tipo de registro DNS (ejemplo: "A", "MX", "TXT").
        
        Retorna:
            Objeto Answer de dnspython con los registros encontrados.
        """
        
        return self.resolver.resolve(dominio, tipo_registro)

    def _resolver_whois_sincrono(self, dominio: str) -> Any:
        """
        Qué hace:
            Realiza una consulta WHOIS de forma síncrona.
        
        Argumentos:
            - dominio: El dominio a consultar (ejemplo: "dominio.com").
        
        Retorna:
            Objeto WhoisEntry con la información del registro del dominio.
        """
        
        return whois.whois(dominio)



    async def _consultar_registros_dns(self, dominio: str) -> Dict[str, List[str]]:
        """
        Qué hace:
            Consulta los registros DNS de un dominio.
        
        Argumentos:
            - dominio: Dominio a consultar.
        
        Variables:
            - registros: Diccionario [tipo_registro: lista_valores] donde se guardan los resultados.
            - event_loop: El event loop de asyncio que gestiona las operaciones async.
            - respuesta: Respuesta cruda del servidor DNS.
            - respuesta_formateada: Registros formateados de forma legible.
        
        Manejo de errores:
            - NXDOMAIN: El dominio no existe en DNS.
            - NoAnswer: El dominio existe pero no tiene ese tipo de registro.
            - Timeout: El servidor DNS no respondió a tiempo.
        
        Retorna:
            Diccionario 'registros' con los resultados de la consulta.
        """
        
        #Se crea el diccionario para almacenar los registros encontrados
        registros: Dict[str, List[str]] = {}
        
        #Se obtiene el event loop actual
        event_loop = asyncio.get_event_loop()
        
        #Se ejecuta la consulta DNS para cada tipo de registro
        for tipo_registro in self.TIPOS_REGISTROS_DNS:
            try:
                respuesta = await event_loop.run_in_executor(   
                    None,
                    self._resolver_dns_sincrono,
                    dominio,
                    tipo_registro
                )
                
                #Se formatean las respuestas para que sean legibles
                respuesta_formateada = self._formatear_respuesta_dns(tipo_registro, respuesta)
                registros[tipo_registro] = respuesta_formateada
            
            #Si hay algun error, se recoge
            except dns.resolver.NXDOMAIN:
                logger.warning(f"DNS_WHOIS  | Error al consultar registro {tipo_registro}: El dominio no existe (NXDOMAIN)")
                
            except dns.exception.Timeout:
                logger.error(f"DNS_WHOIS  | Error al consultar registro {tipo_registro}: Timeout")
                
            except Exception as e:
                logger.error(f"DNS_WHOIS  | Error en la consulta del registro {tipo_registro}: {e}")
        
        return registros



    def _formatear_respuesta_dns(
        self,
        tipo_registro: str,
        respuestas: Any,
    ) -> List[str]:
        """
        Qué hace:
            Convierte las respuestas del servidor DNS a strings legibles.
        
        Argumentos:
            - tipo_registro: Tipo de registro DNS.
            - respuestas: Respuestas del resolver.
        
        Variables:
            - resultados: Lista donde se acumulan los valores formateados.
            - registro: Cada registro individual en la respuesta.
            - valor: String formateado para cada registro.
        
        Retorna:
            Lista de strings con los valores de los registros formateados.
        """
        
        #Se crea la lista para almacenar los resultados formateados
        resultados = []
        
        #Se itera sobre cada registro en la respuesta y se formatea según su tipo
        for registro in respuestas:
            
            #Registros MX: tienen 'prioridad + servidor de correo'
            if tipo_registro == "MX":
                valor = str(registro.preference) + " " + str(registro.exchange)
                resultados.append(valor)
            
            #Registros SOA: tienen 'servidor primario + email'
            elif tipo_registro == "SOA":
                valor = "Primary NS: " + str(registro.mname) + ", Email: " + str(registro.rname)
                resultados.append(valor)
            
            #El resto de tipos se convierten a string
            else:
                resultados.append(str(registro))
        
        return resultados


    def _formatear_fecha(self, fecha) -> str:
        """
        Qué hace:
            Obtiene la primera fecha de una lista de fechas y la pasa a string
        
        Argumentos:
            - fecha: lista de fechas.
        
        Retorna:
            String con la primera fecha de la lista.
        """
        if fecha is None:
            return None
        if isinstance(fecha, list):
            fecha = fecha[0]
        return str(fecha)


    async def _consultar_whois(self, dominio: str) -> Dict[str, Any]:
        """
        Qué hace:
            Obtiene información del registro del dominio desde servidores WHOIS.
        
        Argumentos:
            - dominio: Dominio a consultar.
        
        Variables:
            - event_loop: El event loop de asyncio.
            - datos_whois: Respuesta cruda del servidor WHOIS.
            - resultado: Diccionario donde se almacenan los campos extraídos.
            - resultado_limpio: Diccionario sin los campos con valor None
        
        Retorna:
            Diccionario con información WHOIS relevante.
        """
        
        try:
            #Se obtiene el event loop actual
            event_loop = asyncio.get_event_loop()
            
            #Se ejecuta la consulta WHOIS en un executor
            datos_whois = await event_loop.run_in_executor(
                None,
                self._resolver_whois_sincrono,
                dominio
            )
            
            #Se extraen los campos relevantes de la respuesta WHOIS
            resultado = {}
            resultado["registrador"] = datos_whois.registrar
            resultado["fecha_creacion"] = self._formatear_fecha(datos_whois.creation_date)
            resultado["fecha_expiracion"] = self._formatear_fecha(datos_whois.expiration_date)  
            resultado["name_servers"] = datos_whois.name_servers
            resultado["estado"] = datos_whois.status
            
            #Se usan getattr para org y country porque pueden no existir
            resultado["org"] = getattr(datos_whois, "org", None)
            resultado["pais"] = getattr(datos_whois, "country", None)
            
            #Se filtran los campos que tienen valor None
            resultado_limpio = {}
            for i, registro in resultado.items():
                if registro is not None:
                    resultado_limpio[i] = registro
            
            return resultado_limpio
            
        except Exception as e:
            logger.warning(f"DNS_WHOIS  | Error en consulta WHOIS: {e}")
            return {"error": str(e)}
