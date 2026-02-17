"""
Módulo de identificación de tecnologías utilizadas por la página web objetivo.

Funcionalidades:
    Este módulo genera una recomendación en el reporte con los enlaces necesarios
    para facilitar la identificación manual de tecnologías.
"""

from typing import Dict, Any
from core.session import sesionHttpAsincrona
from core.report_gen import GeneradorReportes
from core import URL_WAPPALYZER



class TechStack:
    """
    Qué hace:
        Esta clase genera una recomendación en el reporte para identificar las tecnologías
        del objetivo utilizando la extensión de Wappalyzer en el navegador.
    
    Atributos específicos de la clase:
        - URL_WAPPALYZER: URL de la extensión de Wappalyzer.
    """
    
    NOMBRE_MODULO: str = "tech_stack"
    CATEGORIA: str = "passive"
    
    
    URL_WAPPALYZER = URL_WAPPALYZER
    
    
    async def run(
        self,
        url: str,
        session: sesionHttpAsincrona,
        report: GeneradorReportes,
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Genera una recomendación en el reporte para que el usuario utilice
            la extensión de Wappalyzer manualmente.
        
        Argumentos:
            url: URL objetivo.
            session: Sesión HTTP asíncrona (no se usa, pero se mantiene para que soda.py llame a todos
                    los módulos de la misma manera).
            report: Reporte en el que se reflejan los hallazgos.
        
        Variables:
            - resultados: Diccionario con la recomendación y los enlaces.
        
        Retorna:
            Diccionario con la recomendación generada.
        """
        
        #Se crea el diccionario con la recomendación
        resultados: Dict[str, Any] = {
            "url_objetivo": url,
            "recomendacion": f"Para identificar las tecnologías utilizadas por el objetivo, se recomienda usar la extensión de Wappalyzer en el navegador.",
            "url_wappalyzer": self.URL_WAPPALYZER,
            "instrucciones": [
                "1. Instala la extensión de Wappalyzer en tu navegador (Chrome, Firefox, Edge).",
                "2. Visita la URL objetivo en el navegador.",
                "3. Haz clic en el icono de Wappalyzer para ver las tecnologías detectadas.",
            ]}
        
        #Se agregan los hallazgos al reporte
        report.añadir_hallazgo(
            nombre_modulo=self.NOMBRE_MODULO,
            categoria=self.CATEGORIA,
            datos=resultados,
        )
        return resultados

