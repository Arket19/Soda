"""
Este módulo genera diagramas Draw.io de la topología web usando un LLM.

Funcionalidades:
    - Procesamiento de URLs descubiertas por el crawler.
    - Generación de diagramas .drawio vía LLM 
    - Extracción y validación de XML desde respuestas del LLM.
"""

import re
import litellm

from pathlib import Path
from urllib.parse import urlparse
from loguru import logger
from core import MAX_TOKENS_LLM
from typing import (
    Dict,
    List,
    Optional,
    Set,
    Any
)

#Template del prompt que se envía al LLM
PLANTILLA_PROMPT_DRAWIO ='''
    Eres un experto en generar diagramas Draw.io en formato XML.

    Tu tarea es generar un archivo .drawio (XML) que represente la estructura jerárquica de un sitio web basándote en las URLs proporcionadas.

    ## Estructura del archivo .drawio

    Un archivo .drawio es un XML con la siguiente estructura:
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <mxfile host="visualizer.py" agent="SODA Web Mapper" version="1.0.0">
    <diagram name="Web Map" id="0">
        <mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" herramientatips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1200" pageHeight="800" math="0" shadow="0">
        <root>
            <mxCell id="0"/>
            <mxCell id="1" parent="0"/>
            <!-- NODOS aquí -->
            <!-- ARISTAS aquí -->
        </root>
        </mxGraphModel>
    </diagram>
    </mxfile>
    ```

    ## Estilos de nodos

    - **Nodo raíz (dominio)**: Verde, redondeado, negrita
    ```
    style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontStyle=1;"
    ```

    - **Directorio**: Azul, redondeado
    ```
    style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    ```

    - **Archivo**: Amarillo, redondeado
    ```
    style="rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"
    ```

    ## Ejemplo de nodo
    ```xml
    <mxCell id="n1" value="example.com" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;fontStyle=1;" vertex="1" parent="1">
    <mxGeometry x="500" y="50" width="140" height="70" as="geometry"/>
    </mxCell>
    ```

    ## Ejemplo de arista (conexión)
    ```xml
    <mxCell id="e1" edge="1" parent="1" source="n1" objetivo="n2" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;">
    <mxGeometry relative="1" as="geometry"/>
    </mxCell>
    ```

    ## Reglas de layout

    1. El nodo raíz (dominio) debe estar centrado en la parte superior
    2. Los nodos hijos se distribuyen debajo del padre
    3. Usa un layout jerárquico (árbol) de arriba hacia abajo
    4. Espacia los nodos para evitar superposiciones (mínimo 150px horizontal, 100px vertical)
    5. Los archivos (.html, .php, .js, .css, etc.) van en amarillo
    6. Los directorios van en azul
    7. Conecta cada nodo hijo con su padre mediante aristas
    8. Ajusta pageWidth y pageHeight según el tamaño del diagrama

    ## Datos del sitio web

    **Dominio**: {domain}

    **Rutas descubiertas** (una por línea):
    {paths}

    ## Instrucciones

    1. Analiza las rutas y construye la jerarquía
    2. Genera el XML completo del archivo .drawio
    3. Asigna IDs únicos a cada nodo (n1, n2, ...) y arista (e1, e2, ...)
    4. Calcula posiciones X,Y apropiadas para un layout legible
    5. El nodo raíz debe tener width=140, height=70
    6. Los demás nodos deben tener width=120, height=30

    Responde ÚNICAMENTE con el XML del archivo .drawio, sin explicaciones adicionales.
'''

class Visualizer:
    """
    Qué hace:
        Genera diagramas Draw.io de la topología web usando un LLM.
        Procesa URLs descubiertas y las convierte en un diagrama visual
        que muestra la estructura jerárquica del sitio.
    """

    NOMBRE_MODULO: str = "visualizer"
    CATEGORIA: str = "map"

    def __init__(
        self,
        directorio_salida: str = None,
        clave_api: str = None,
        modelo: str = None,
    ):
        """
        Qué hace:
            Inicializa el visualizador con las credenciales del LLM y
            el directorio donde se guardarán los archivos generados.

        Argumentos:
            - directorio_salida: Directorio donde guardar los archivos generados.
            - clave_api: API Key del LLM.
            - modelo: Modelo a utilizar.

        Atributos de instancia creados:
            - self.directorio_salida: Almacena el directorio de salida.
            - self.clave_api: Almacena la API key.
            - self.modelo: Almacena el modelo a usar.
            - self.contador_rutas: Contador de rutas procesadas.
        """

        #Se almacenan las credenciales y el directorio de salida
        self.directorio_salida = directorio_salida
        self.clave_api = clave_api
        self.modelo = modelo
        self.contador_rutas = 0



    async def run(
        self,
        url: str,
        session,
        reporte = None
    ) -> Dict[str, Any]:
        """
        Qué hace:
            Método de interfaz estándar de módulo SODA. Obtiene las URLs
            descubiertas por el crawler desde el reporte y genera el diagrama
            Draw.io (o el archivo manual si no hay API key).

        Argumentos:
            - url: URL objetivo del escaneo.
            - session: Sesión HTTP (no se usa en este módulo, puede ser None).
            - reporte: Objeto GeneradorReportes con los hallazgos previos.
            - **kwargs: Argumentos adicionales.

        Variables:
            - hallazgos_map: Lista de hallazgos de la categoría 'map'.
            - hallazgo: Cada hallazgo durante la iteración.
            - urls_crawler: Lista de URLs descubiertas por el crawler.
            - archivo_salida: Ruta al archivo .drawio de salida.
            - resultado: Ruta al archivo generado.

        Por qué se hace así:
            - Se buscan los datos del crawler en el reporte porque el visualizer
              depende de los resultados del crawler para generar el diagrama.
            - Se usa generate_from_urls() para reutilizar la lógica existente.

        Retorna:
            Diccionario con los resultados del visualizer, o None si falla.
        """

        logger.info(f"VISUALIZER | Iniciando visualización de {url}")

        #Se buscan las URLs descubiertas combinando crawler y discoverer
        urls_combinadas = set()
        modulos_origen = []

        if reporte:
            hallazgos_map = reporte.obtener_hallazgos_por_categoria("map")

            for hallazgo in hallazgos_map:
                if hallazgo.nombre_modulo in ("crawler", "discoverer"):
                    urls_hallazgo = hallazgo.datos.get("urls", [])
                    if urls_hallazgo:
                        urls_combinadas.update(urls_hallazgo)
                        modulos_origen.append(hallazgo.nombre_modulo)

        urls_crawler = list(urls_combinadas)

        if not urls_crawler:
            logger.warning(f"VISUALIZER | No se encontraron URLs de crawler ni discoverer en el reporte")
            return None

        logger.info(f"VISUALIZER | {len(urls_crawler)} URLs de {', '.join(modulos_origen)} encontradas")

        #Se define la ruta del archivo de salida
        if self.directorio_salida:
            archivo_salida = str(Path(self.directorio_salida) / "web_map.drawio")
        else:
            archivo_salida = "web_map.drawio"

        #Se genera el diagrama (o archivo manual si no hay API key)
        resultado = self.generate_from_urls(
            urls=urls_crawler,
            output_file=archivo_salida,
            base_url=url,
        )

        if resultado:
            ruta_drawio_absoluta = str(Path(archivo_salida).resolve())

            return {
                "archivo_generado": resultado,
                "archivo_drawio": ruta_drawio_absoluta,
                "urls_procesadas": len(urls_crawler),
                "rutas_unicas": self.contador_rutas,
                "modo": "automatico" if self.clave_api else "manual",
            }

        return None



    def _llamar_llm(self, prompt: str) -> str:
        """
        Qué hace:
            Realiza la llamada al LLM para generar el XML del diagrama.

        Argumentos:
            - prompt: Prompt completo con las instrucciones y datos.

        Variables:
            - respuesta: Respuesta del LLM.
            - contenido: Texto de la respuesta.

        Retorna:
            Respuesta del LLM (XML del diagrama).
        """

        logger.info(f"VISUALIZER | Llamando a {self.modelo} para generar diagrama...")

        #Se realiza la llamada al LLM
        try:
            respuesta = litellm.completion(
                model=self.modelo,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=MAX_TOKENS_LLM,
                api_key=self.clave_api,
            )

            contenido = respuesta.choices[0].message.content
            logger.debug(f"VISUALIZER | Respuesta del LLM recibida")

            return contenido

        except Exception as error:
            logger.error(f"Error en llamada al LLM: {error}")
            raise RuntimeError(f"VISUALIZER | Error generando diagrama: {error}")



    def _extraer_xml(self, respuesta: str) -> str:
        """
        Qué hace:
            Extrae el XML del diagrama de la respuesta del LLM.

        Argumentos:
            - respuesta: Respuesta completa del LLM.

        Variables:
            - patron_bloque_codigo: Regex para encontrar bloques de código.
            - coincidencias: Bloques de código encontrados.
            - inicio: Posición inicial del XML.
            - fin: Posición final del XML.

        Por qué se necesita extracción:
            El LLM puede incluir el XML dentro de bloques de código
            Markdown (```xml ... ```) o con texto adicional. Esta
            función limpia la respuesta para obtener solo el XML.

        Retorna:
            XML limpio del diagrama.
        """

        #Intentar extraer de bloque de código Markdown
        patron_bloque_codigo = r'```(?:xml)?\s*([\s\S]*?)```'
        coincidencias = re.findall(patron_bloque_codigo, respuesta)

        if coincidencias:
            #Buscar el bloque que contenga mxfile
            for coincidencia in coincidencias:
                if '<mxfile' in coincidencia:
                    return coincidencia.strip()
            #Si no hay mxfile, usar el primer bloque
            return coincidencias[0].strip()

        #Si no hay bloques de código, buscar el XML directamente
        if '<mxfile' in respuesta:
            inicio = respuesta.find('<?xml')
            if inicio == -1:
                inicio = respuesta.find('<mxfile')
            fin = respuesta.rfind('</mxfile>') + len('</mxfile>')
            return respuesta[inicio:fin].strip()

        #Devolver la respuesta tal cual como último recurso
        return respuesta.strip()



    def _generar_archivo_manual(
        self,
        urls: List[str],
        output_file: str,
        base_url: str,
    ) -> str:
        """
        Qué hace:
            Genera un archivo de texto con el prompt y las rutas descubiertas
            para que el usuario pueda copiarlo manualmente a un LLM en el
            navegador y obtener el diagrama Draw.io sin necesidad de API key.

        Argumentos:
            - urls: Lista de URLs descubiertas.
            - output_file: Ruta base para el archivo de salida.
            - base_url: URL base del sitio.

        Variables:
            - rutas: Set de paths únicos extraídos de las URLs.
            - url: Cada URL de la lista.
            - parseada: Componentes de cada URL.
            - path: Path de cada URL.
            - dominio: Dominio del sitio.
            - texto_rutas: Rutas formateadas como texto.
            - prompt: Prompt completo para el LLM.
            - ruta_archivo: Path del archivo de salida.

        Retorna:
            Ruta al archivo generado, o cadena vacía si falla.
        """

        #Se extraen los paths únicos de las URLs
        rutas = set()
        for url in urls:
            parseada = urlparse(url)
            path = parseada.path or "/"

            #Normalizar path
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")

            rutas.add(path)

        rutas = sorted(rutas)
        self.contador_rutas = len(rutas)

        if not rutas:
            logger.warning("No se encontraron rutas para visualizar")
            return ""

        #Se construye el prompt completo
        dominio = urlparse(base_url).netloc
        texto_rutas = "\n".join(rutas)
        prompt = PLANTILLA_PROMPT_DRAWIO.format(
            domain=dominio,
            paths=texto_rutas
        )

        #Se guarda el archivo con el prompt listo para copiar
        ruta_archivo = Path(output_file).parent / "paths_for_llm.txt"
        ruta_archivo.parent.mkdir(parents=True, exist_ok=True)

        with open(ruta_archivo, 'w', encoding='utf-8') as archivo:
            archivo.write(prompt)

        #Se crea el archivo .drawio vacío para que el auditor guarde el codigo del Drawio
        ruta_drawio = Path(output_file)
        ruta_drawio.touch()

        logger.success(
            f"VISUALIZER | Archivo generado para uso manual con LLM: {ruta_archivo.resolve()}"
        )

        return str(ruta_archivo.resolve())



    def generate_from_urls(
        self,
        urls: List[str],
        output_file: str,
        base_url: str
    ) -> str:
        """
        Qué hace:
            Genera un diagrama Draw.io desde una lista de URLs en memoria.

        Argumentos:
            - urls: Lista de URLs descubiertas.
            - output_file: Ruta donde guardar el archivo .drawio.
            - base_url: URL base del sitio.

        Variables:
            - rutas: Set de paths únicos.
            - url: Cada URL de la lista.
            - parseada: Componentes de cada URL.
            - dominio_url: Dominio de cada URL.
            - path: Path de cada URL.
            - dominio: Dominio para el diagrama.
            - texto_rutas: Rutas formateadas.
            - prompt: Prompt para el LLM.
            - respuesta: Respuesta del LLM.
            - contenido_xml: XML extraído.
            - ruta_salida: Path del archivo de salida.

        Retorna:
            Ruta al archivo generado, o cadena vacía si falla.
        """

        #Se comprueba si se ha proporcionado api key 
        if not self.clave_api or not self.modelo:
            logger.warning("No se proporcionaron API Key y/o modelo. Generando archivo de rutas para uso manual con LLM.")
            return self._generar_archivo_manual(urls, output_file, base_url)

        logger.info(f"VISUALIZER | Generando diagrama...")

        #Se extraen paths únicos de las URLs
        rutas = set()
        for url in urls:
            parseada = urlparse(url)
            path = parseada.path or "/"

            #Se normaliza el path
            if path != "/" and path.endswith("/"):
                path = path.rstrip("/")

            rutas.add(path)

        rutas = sorted(rutas)
        self.contador_rutas = len(rutas)
        logger.info(f"VISUALIZER | Rutas únicas encontradas: {self.contador_rutas}")

        if not rutas:
            logger.warning("VISUALIZER | No se encontraron rutas para visualizar")
            return ""

        #Se construye el prompt
        dominio = urlparse(base_url).netloc
        texto_rutas = "\n".join(rutas)
        prompt = PLANTILLA_PROMPT_DRAWIO.format(
            domain=dominio,
            paths=texto_rutas
        )

        #Llamar al LLM
        try:
            respuesta = self._llamar_llm(prompt)
        except RuntimeError as error:
            logger.error(str(error))
            return ""

        #Se extrae el XML
        contenido_xml = self._extraer_xml(respuesta)

        #Se guarda el archivo
        ruta_salida = Path(output_file)
        ruta_salida.parent.mkdir(parents=True, exist_ok=True)

        with open(ruta_salida, 'w', encoding='utf-8') as archivo:
            archivo.write(contenido_xml)

        #Se valida que la respuesta contenga la estructura básica
        if '<mxfile' not in contenido_xml:
            logger.error("VISUALIZER | La respuesta del LLM no contiene un diagrama válido")
            #return ""
            return str(ruta_salida.resolve())

        

        logger.success(f"VISUALIZER | Diagrama generado: {ruta_salida.resolve()}")
        return str(ruta_salida.resolve())