"""
Este módulo analiza las cabeceras HTTP de respuesta para identificar la presencia o ausencia de cabeceras de seguridad.
Las recomendaciones se basan en el 'OWASP Secure Headers Project' (https://owasp.org/www-project-secure-headers/)

Funcionalidades:
    - Detección de cabeceras de seguridad.
    - Identificación de configuraciones inseguras en las cabeceras.
    - Fingerprinting del servidor mediante cabeceras reveladoras.
    - Descarga dinámica de las recomendaciones OWASP (con fallback hardcodeado).
"""

import re
import httpx
from typing import Dict, Any
from loguru import logger
from core.session import sesionHttpAsincrona
from core.report_gen import GeneradorReportes
from core import (
    URL_OWASP_HEADERS_ADD,
    URL_OWASP_HEADERS_REMOVE,
    FALLBACK_HEADERS_RECOMENDADOS,
    FALLBACK_HEADERS_QUITAR,
)



class HeadersAnalyzer:
    """
    Qué hace:
        Esta clase analiza las cabeceras HTTP de la respuesta del servidor para evaluar
        si están bien configuradas, comparándolas con las recomendaciones de OWASP.
        Si estas no están disponibles, se utiliza un fallback hardcodeado.
    
    Atributos específicos de la clase:
        - URL_OWASP_HEADERS_ADD: URL del JSON de cabeceras a añadir.
        - URL_OWASP_HEADERS_REMOVE: URL del JSON de cabeceras a eliminar.
        - FALLBACK_HEADERS_RECOMENDADOS: Lista de cabeceras recomendadas por OWASP.
        - FALLBACK_HEADERS_QUITAR: Lista de cabeceras que pueden revelar información del servidor.
    """
    
    NOMBRE_MODULO: str = "headers_analyzer"
    CATEGORIA: str = "passive"
    
    
    URL_OWASP_HEADERS_ADD = URL_OWASP_HEADERS_ADD
    URL_OWASP_HEADERS_REMOVE = URL_OWASP_HEADERS_REMOVE
    FALLBACK_HEADERS_RECOMENDADOS = FALLBACK_HEADERS_RECOMENDADOS
    FALLBACK_HEADERS_QUITAR = FALLBACK_HEADERS_QUITAR


    def __init__(self) -> None:
        """
        Qué hace:
            Inicializa el analizador de cabeceras.
        
        Atributos de instancia creados:
            - self.valores_recomendados: Diccionario con valores recomendados por OWASP (se carga en run).
            - self.cabeceras_a_eliminar: Lista de cabeceras reveladoras a detectar (se carga en run).
        """
        
        #Inicialmente se usan los fallbacks, luego se actualizan en run() si hay conexión
        self.valores_recomendados = self.FALLBACK_HEADERS_RECOMENDADOS.copy()
        self.cabeceras_a_eliminar = self.FALLBACK_HEADERS_QUITAR.copy()



    async def run(
        self,
        url: str,
        session: sesionHttpAsincrona,
        report: GeneradorReportes,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Ejecuta el análisis de cabeceras HTTP de la URL objetivo.
        
        Argumentos:
            url: URL objetivo para analizar.
            session: Sesión HTTP asíncrona.
            report: Reporte en el que se reflejan los hallazgos.
        
        Variables:
            - resultados: Diccionario con los hallazgos del análisis.
            - respuesta: Respuesta HTTP del servidor.
            - cabeceras: Diccionario con todas las cabeceras de la respuesta.
            - analisis_seguridad: Resultado del análisis de cabeceras de seguridad.
            - fingerprint: Información identificativa del servidor.
            - recomendaciones: Lista de recomendaciones de mejora basadas en OWASP.
        
        Retorna:
            Diccionario con el análisis completo de cabeceras.
        """
        
        logger.info(f"HEADERS    | Iniciando análisis de cabeceras...")
        
        #Se descargan las recomendaciones actualizadas desde OWASP
        await self._cargar_datos_owasp()
        
        #Se crea el diccionario para almacenar todos los resultados
        resultados: Dict[str, Any] = {
            "url": url,
            "cabeceras_seguras": {
                "presentes": {},
                "ausentes": [],
            },
            "cabeceras_eliminables": {},
            "cabeceras_objetivo": {},
            "errores": [],
        }
        
        try:
            #Se realiza una petición GET para obtener las cabeceras
            respuesta = await session.get(url)
            
            #Si no hay respuesta, se registra el error y se retorna
            if respuesta is None:
                resultados["errores"].append("No se pudo obtener respuesta del servidor")
                return resultados
            
            #Se extraen las cabeceras de la respuesta
            cabeceras_objetivo = dict(respuesta.headers)
            resultados["cabeceras_objetivo"] = cabeceras_objetivo

            #Se compran las cabeceras del objetivo con las recomendadas
            cabeceras_seguras = self.comparar_objetivo_recomendables(cabeceras_objetivo)
            resultados["cabeceras_seguras"] = cabeceras_seguras

            #Se buscan las cabeceras del objetivo que deberían eliminarse
            cabeceras_eliminables = self.comparar_objetivo_eliminables(cabeceras_objetivo)
            resultados["cabeceras_eliminables"] = cabeceras_eliminables
            
            logger.info(f"HEADERS    | Análisis completado. {len(cabeceras_seguras['ausentes'])} cabeceras ausentes.")
            
        except Exception as e:
            logger.error(f"HEADERS    | Error analizando {url}: {e}")
            resultados["errores"].append(str(e))
        
        #Se agregan los hallazgos al reporte
        report.añadir_hallazgo(
            nombre_modulo=self.NOMBRE_MODULO,
            categoria=self.CATEGORIA,
            datos=resultados,
        )
        
        return resultados
    


    def comparar_objetivo_recomendables(
        self,
        cabeceras_objetivo: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Compara las cabeceras del objetivo y sus valores con las recomendadas por OWASP.
        
        Argumentos:
            - cabeceras_objetivo: Diccionario de cabeceras HTTP detectadas en la respuesta del objetivo.
        
        Variables:
            - cabeceras_objetivo_normalizadas: Diccionario con los nombres de las cabeceras del objetivo en minúsculas para comparación.
            - presentes: Diccionario con las cabeceras de seguridad recomendadas presentes entre las cabeceras del objetivo.
            - ausentes: Lista con las cabeceras de seguridad recomendadas ausentes entre las cabeceras del objetivo.
        
        Retorna:
            Diccionario con las cabeceras de seguridad recomendadas presentes y ausentes.
        """
        
        cabeceras_objetivo_normalizadas = {}
        presentes = {}
        ausentes = []

        #Se normalizan los nombres de cabeceras a minúsculas para comparación case-insensitive
        for cabecera, valor in cabeceras_objetivo.items(): 
            cabeceras_objetivo_normalizadas[cabecera.lower()] = (cabecera, valor)
        
        #Se verifica si cada cabecera recomendada está presente en la respuesta del objetivo
        for cabecera_recomendada in self.valores_recomendados.keys():
            cabecera_recomendada_normalizada = cabecera_recomendada.lower()
            
            #Si la cabecera está presente, se verifica si su valor es seguro
            if cabecera_recomendada_normalizada in cabeceras_objetivo_normalizadas:
                nombre_original, valor = cabeceras_objetivo_normalizadas[cabecera_recomendada_normalizada]
                presentes[nombre_original] = {
                    "valor": valor,
                    "seguro": self._es_valor_seguro(cabecera_recomendada, valor),
                }
            else:
                ausentes.append(cabecera_recomendada)
        
        return {
            "presentes": presentes,
            "ausentes": ausentes,
        }
    


    def _es_valor_seguro(self, nombre_cabecera: str, valor: str) -> bool:
        """
        Qué hace:
            Verifica si el valor de una cabecera de seguridad es adecuado según OWASP.
            Cada cabecera tiene sus propios criterios de validación basados en las
            recomendaciones del OWASP Secure Headers Project.
        
        Argumentos:
            - nombre_cabecera: Nombre de la cabecera a verificar.
            - valor: Valor actual de la cabecera en la respuesta del servidor.
        
        Variables:
            - valor_lower: Valor en minúsculas para comparación case-insensitive.
            - nombre_lower: Nombre de la cabecera en minúsculas para comparación.
            - max_age_match: Resultado de buscar el valor max-age en HSTS.
            - max_age: Valor numérico de max-age extraído de HSTS.
        
        Retorna:
            True si la configuración es segura, False en caso contrario.
        """
        
        #Se normalizan ambos valores a minúsculas para comparaciones case-insensitive
        valor_lower = valor.lower().strip()
        nombre_lower = nombre_cabecera.lower()
        
        if nombre_lower == "strict-transport-security":
            #Se busca el valor de max-age usando una expresión regular
            max_age_match = re.search(r'max-age=(\d+)', valor_lower)
            
            if not max_age_match:
                return False

            max_age = int(max_age_match.group(1))
            
            if max_age < 15768000:
                return False
            
            return True
        
        if nombre_lower == "x-frame-options":
            valores_seguros = ["deny", "sameorigin"]
            return valor_lower in valores_seguros
        
        if nombre_lower == "x-content-type-options":
            return valor_lower == "nosniff"
        
        if nombre_lower == "referrer-policy":

            valores_seguros = [
                "no-referrer",
                "no-referrer-when-downgrade",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "same-origin",
                "origin",
                "origin-when-cross-origin",
            ]
            return valor_lower in valores_seguros
        
        if nombre_lower == "content-security-policy":

            if "unsafe-inline" in valor_lower and "nonce-" not in valor_lower and "sha256-" not in valor_lower:
                return False
            
            if "unsafe-eval" in valor_lower:
                return False
            
            if "default-src" not in valor_lower and "script-src" not in valor_lower:
                return False
            
            return True
        
        if nombre_lower == "x-dns-prefetch-control":
            return valor_lower == "off"
        
        if nombre_lower == "permissions-policy":
            #Si está vacío no aporta seguridad
            if not valor_lower or valor_lower == "":
                return False
            
            return True
        
        if nombre_lower == "cross-origin-opener-policy":
            valores_seguros = ["same-origin", "same-origin-allow-popups"]
            return valor_lower in valores_seguros
        
        if nombre_lower == "cross-origin-embedder-policy":
            valores_seguros = ["require-corp", "credentialless"]
            return valor_lower in valores_seguros
        
        if nombre_lower == "cross-origin-resource-policy":
            valores_seguros = ["same-origin", "same-site"]
            return valor_lower in valores_seguros
        
        if nombre_lower == "x-permitted-cross-domain-policies":
            valores_seguros = ["none", "master-only"]
            return valor_lower in valores_seguros
        
        if nombre_lower == "cache-control":
            if "no-store" in valor_lower:
                return True
            
            if "private" in valor_lower and "no-cache" in valor_lower:
                return True
            
            return False
        
        if nombre_lower == "clear-site-data":
            
            tipos_limpieza = ["cache", "cookies", "storage", "*"]
            
            for tipo in tipos_limpieza:
                if tipo in valor_lower:
                    return True
            
            return False
        
        return True



    def comparar_objetivo_eliminables(
        self,
        cabeceras_objetivo: Dict[str, str],
    ) -> Dict[str, str]:
        """
        Qué hace:
            Compara las cabeceras del objetivo con las que OWASP recomienda eliminar.
        
        Argumentos:
            - cabeceras_objetivo: Diccionario de cabeceras HTTP detectadas en la respuesta del objetivo.
        
        Variables:
            - cabeceras_objetivo_normalizadas: Diccionario con los nombres de las cabeceras del objetivo en minúsculas para comparación.
            - presentes: Diccionario con las cabeceras de seguridad que OWASP recomienda eliminar presentes entre las cabeceras del objetivo.
        
        Retorna:
            Diccionario con las cabeceras de seguridad presentes en el objetivo que OWASP recomienda eliminar.
        """

        cabeceras_objetivo_normalizadas = {}
        presentes = {}

        #Se normalizan las cabeceras a minúsculas para comparación case-insensitive
        for cabecera, valor in cabeceras_objetivo.items():
            cabeceras_objetivo_normalizadas[cabecera.lower()] = (cabecera, valor)
        
        #Se buscan cabeceras eliminables entre las cabeceras del objetivo
        for cabecera_eliminable in self.cabeceras_a_eliminar:
            cabecera_eliminable_normalizada = cabecera_eliminable.lower()

            if cabecera_eliminable_normalizada in cabeceras_objetivo_normalizadas:
                nombre_original, valor = cabeceras_objetivo_normalizadas[cabecera_eliminable_normalizada]
                presentes[nombre_original] = valor
        
        return presentes



    async def _cargar_datos_owasp(self) -> None:
        """
        Qué hace:
            Intenta descargar los archivos JSON de OWASP con las recomendaciones actualizadas. Si no se puede conectar, utiliza los datos hardcodeados como fallback.
        
        Variables:
            - cliente_http: Cliente HTTP asíncrono para las peticiones.
            - respuesta_add: Respuesta HTTP del JSON headers_add.
            - respuesta_remove: Respuesta HTTP del JSON headers_remove.
            - datos_add: Contenido parseado del JSON headers_add.
            - datos_remove: Contenido parseado del JSON headers_remove.

        Retorna:
            None.
        """
        
        try:
            #Se crea un cliente HTTP con timeout corto para no bloquear mucho tiempo
            async with httpx.AsyncClient(timeout=5.0) as cliente_http:
                
                #Se descargan los dos JSON con las recomendaciones de OWASP actualizadas
                respuesta_add = await cliente_http.get(self.URL_OWASP_HEADERS_ADD)
                respuesta_remove = await cliente_http.get(self.URL_OWASP_HEADERS_REMOVE)
                
                #Si el código de respuesta de headers_add es exitoso, se procesan los datos
                if respuesta_add.status_code == 200:
                    datos_add = respuesta_add.json()
                    self.valores_recomendados = {}

                    #Se convierte la lista de objetos a diccionario
                    for cabecera in datos_add.get("headers", []):
                        nombre_cabecera = cabecera.get("name")
                        valor_cabecera = cabecera.get("value")
                        if nombre_cabecera and valor_cabecera:
                            self.valores_recomendados[nombre_cabecera] = valor_cabecera
                    
                    logger.debug(f"HEADERS    | Cargadas las cabeceras recomendadas desde OWASP")
                
                #Si el código de respuesta de headers_remove es exitoso, se procesan los datos
                if respuesta_remove.status_code == 200:
                    datos_remove = respuesta_remove.json()
                    self.cabeceras_a_eliminar = datos_remove.get("headers", [])

                    logger.debug(f"HEADERS    | Cargadas las cabeceras que se recomiendan eliminar desde OWASP")

        #Si hay cualquier error, se usan los fallbacks   
        except Exception as e:
            logger.warning(f"HEADERS    | No se pudo conectar con OWASP, usando recomendaciones de cabeceras locales. Error: {e}")
