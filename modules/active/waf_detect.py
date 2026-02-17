"""
    Detecta si el sitio web objetivo está protegido por un WAF
    (Web Application Firewall) e intenta identificar cuál es.

Funcionalidades:
    - Detectar la presencia de WAF en la página web objetivo
    - Determinar qué WAF se está utilizando
"""

import asyncio
import re
from typing import Dict, Any, Optional

from loguru import logger

from core.session import sesionHttpAsincrona
from core.report_gen import GeneradorReportes
from core import FIRMAS_WAF, PAYLOADS_PRUEBA



class WAFDetect:
    """
    Qué hace:
        Detector de Web Application Firewalls que utiliza distintas
        técnicas para identificar la presencia y tipo de WAF.

    Atributos específicos de la clase:
        - FIRMAS_WAF: Diccionario con firmas de cada WAF conocido.
        - PAYLOADS_PRUEBA: Payloads para provocar bloqueos.
    """


    NOMBRE_MODULO: str = "waf_detect"
    CATEGORIA: str = "active"


    FIRMAS_WAF = FIRMAS_WAF
    PAYLOADS_PRUEBA = PAYLOADS_PRUEBA



    def __init__(self) -> None:
        """
        Qué hace:
            Inicializa el detector de WAF.

        Está vacío porque los parámetros están definidos como constantes de clase.
        """
        logger.debug("WAF_DETECT | WAFDetect inicializado")



    async def run(
        self,
        url: str,
        session: sesionHttpAsincrona,
        report: Optional[GeneradorReportes] = None 
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Ejecuta la detección de WAF en la URL objetivo.

        Argumentos:
            - url: URL del sitio a analizar.
            - session: Sesión HTTP asíncrona.
            - report: Generador de reportes.

        Variables:
            - resultados: Diccionario con todos los resultados.
            - deteccion_pasiva: Resultados del análisis de headers.
            - deteccion_activa: Resultados del envío de payloads.

        Flujo de ejecución:
            1. Fase pasiva: Analiza headers y cookies
            2. Fase activa: Envía payloads maliciosos
            3. Combina resultados
            4. Añade al reporte

        Retorna:
            Diccionario con información del WAF detectado.
        """

        logger.info(f"WAF_DETECT | Detectando WAF en: {url}")


        #Se inicializa el diccionario de resultados 
        resultados: Dict[str, Any] = {
            "url": url,
            "waf_detected": False,
            "waf_name": None,
            "detection_method": [],
            "evidence": [],
            "errors": [],
        }

        try:
            #Detección pasiva por headers y cookies
            deteccion_pasiva = await self._detectar_por_headers(url, session)
            if deteccion_pasiva["detected"]:
                resultados["waf_detected"] = True
                resultados["waf_name"] = deteccion_pasiva["waf_name"]
                resultados["evidence"] = deteccion_pasiva["evidence"]
                resultados["detection_method"].append("headers")
                
            #Detección activa por payloads
            deteccion_activa = await self._detectar_por_payloads(url, session)
            if deteccion_activa["blocked"]:
                resultados["waf_detected"] = True
                resultados["detection_method"].append("blocked_payloads")

            #Log del resultado
            nombre_waf = resultados["waf_name"] or "No detectado"
            logger.info(f"WAF_DETECT | Resultado: {nombre_waf}")


        except Exception as error:
            logger.error(f"WAF_DETECT | Error durante detección: {error}")
            resultados["errors"].append(str(error))


        #Agregar resultados al reporte
        if report:
            report.añadir_hallazgo(
                nombre_modulo=self.NOMBRE_MODULO,
                categoria=self.CATEGORIA,
                datos=resultados,
            )

        return resultados



    async def _detectar_por_headers(
        self,
        url: str,
        sesion: sesionHttpAsincrona
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Detecta WAF analizando headers y cookies de la respuesta.

        Argumentos:
            - url: URL a analizar.
            - sesion: Sesión HTTP.

        Variables:
            - resultado: Diccionario con el resultado de detección.
            - respuesta: Respuesta HTTP.
            - headers: Headers de la respuesta en minúsculas.
            - cookies: String con las cookies de la respuesta.
            - nombre_waf: Nombre del WAF encontrado.
            - firmas: Firmas del WAF actual.
            - header: Cada header a buscar.
            - patron: Patrón regex a buscar.
            - cookie: Cada cookie a buscar.

        Retorna:
            Diccionario con detected, waf_name y evidence.
        """

        resultado = {
            "detected": False,
            "waf_name": None,
            "evidence": []
        }

        #Se hace una petición al sitio para ver si responde
        respuesta = await sesion.get(url)
        if not respuesta:
            return resultado

        #Se convierten los headers a minúsculas para comparación
        headers = {}
        for clave, valor in respuesta.headers.items():
            headers[clave.lower()] = valor

        #Se obtienen las cookies
        cookies = respuesta.headers.get("set-cookie", "").lower()


        for nombre_waf, firmas in self.FIRMAS_WAF.items():
            
            #Se buscan firmas de WAFs comunes en los headers
            headers_firmas = firmas.get("headers", {})
            for header, patron in headers_firmas.items():
                header_lower = header.lower()
                if header_lower in headers:
                    if re.search(patron, headers[header_lower], re.IGNORECASE):
                        resultado["detected"] = True
                        resultado["waf_name"] = nombre_waf
                        resultado["evidence"].append(header)
                        return resultado

            #Se buscan firmas de WAFs comunes en cookies
            cookies_firmas = firmas.get("cookies", [])
            for cookie in cookies_firmas:
                if cookie.lower() in cookies:
                    resultado["detected"] = True
                    resultado["waf_name"] = nombre_waf
                    resultado["evidence"].append(cookie)
                    return resultado

        return resultado



    async def _detectar_por_payloads(
        self,
        url: str,
        sesion: sesionHttpAsincrona
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Detecta WAF enviando payloads maliciosos y observando la respuesta.

        Argumentos:
            - url: URL base del sitio.
            - sesion: Sesión HTTP.

        Variables:
            - resultado: Diccionario con el resultado.
            - baseline: Respuesta normal del sitio.
            - payload: Cada payload a probar.
            - url_prueba: URL con el payload inyectado.
            - respuesta: Respuesta del servidor.

        Retorna:
            Diccionario con blocked y blocked_payloads.
        """

        resultado = {
            "blocked": False,
            "blocked_payloads": []
        }

        #Se prueba cada payload añadiendolo a la URL
        for payload in self.PAYLOADS_PRUEBA:

            url_base = url.rstrip("/")
            url_prueba = f"{url_base}?{payload['param']}={payload['value']}"

            #Códigos comunes de bloqueo por WAF
            codigos_bloqueo = [401, 403, 406, 429, 503] 

            #Se hace la petición y se comprueba si es bloqueada
            respuesta = await sesion.get(url_prueba)
            
            if respuesta and respuesta.status_code in codigos_bloqueo:
                resultado["blocked"] = True
                resultado["blocked_payloads"].append(payload["name"])

            #Delay para no hacer peticiones demasiado seguido
            await asyncio.sleep(1)

        return resultado

