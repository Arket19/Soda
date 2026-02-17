"""
Este módulo centraliza la recolección de resultados de todos los
módulos de escaneo y exporta los hallazgos en JSON

Funcionalidades:
    - Recolección de hallazgos de todos los módulos
    - Carga y actualización de informes previos
    - Exportación a JSON de los hallazgos
"""

import json

from datetime import datetime
from pathlib import Path
from loguru import logger
from typing import (
    Dict,
    List,
    Any,
    Optional,
)
from core import (
    NOMBRE_PROYECTO,
    VERSION,
)



class Hallazgo:
    """
    Qué hace:
        Representa cada uno de los hallazgos individuales de los módulos
        que serán agregados al reporte final.
    """

    def __init__(
        self,
        nombre_modulo: str,
        categoria: str,
        datos: Dict[str, Any],
        timestamp: Optional[datetime] = None,
    ) -> None:
        """
        Qué hace:
            Inicializa un hallazgo con los datos proporcionados.

        Argumentos:
            - nombre_modulo: Nombre del módulo origen.
            - categoria: Categoría del escaneo.
            - datos: Diccionario con los datos descubiertos.
            - timestamp: Momento del hallazgo (argumento opcional, se usa al cargar hallazgos previos).

        Atributos de instancia creados:
            - self.nombre_modulo: Almacena el nombre del módulo.
            - self.categoria: Almacena la categoría.
            - self.datos: Almacena los datos del hallazgo.
            - self.timestamp: Almacena el momento (si no se proporciona, usa ahora).
        """
        
        self.nombre_modulo = nombre_modulo
        self.categoria = categoria
        self.datos = datos
        self.timestamp = timestamp or datetime.now()



    def to_dict(self) -> Dict[str, Any]:
        """
        Qué hace:
            Convierte el hallazgo a un diccionario para poder serializarlo a JSON.
            Esto es necesario porque JSON no puede serializar objetos de Python directamente.
            Es el proceso inverso a from_dict().

        Variables:
            - diccionario_resultado: Diccionario creado a partir de los atributos del objeto.

        Retorna:
            Diccionario con los campos module, categoria, timestamp y data.
        """
        
        diccionario_resultado = {
            "module": self.nombre_modulo,
            "categoria": self.categoria,
            "timestamp": self.timestamp.isoformat(),
            "data": self.datos,
        }
        
        return diccionario_resultado



    @classmethod #Permite crear objeto directamente desde un diccionario sin tener que instanciar primero el objeto Hallazgo
    def from_dict(cls, diccionario: Dict[str, Any]) -> "Hallazgo":
        """
        Qué hace:
            Crea un objeto Hallazgo desde un diccionario.
            Es el proceso inverso a to_dict().

        Argumentos:
            - diccionario: Diccionario con los campos del hallazgo.

        Variables:
            - timestamp_parseado: Objeto datetime creado desde la cadena ISO.

        Retorna:
            Nueva instancia de Hallazgo con los datos del diccionario.
        """
        
        #Se convierte el timestamp de formato ISO a objeto datetime
        timestamp_parseado = datetime.fromisoformat(diccionario["timestamp"])
        
        #Se crea y retorna el objeto Hallazgo
        return cls(
            nombre_modulo=diccionario["module"],
            categoria=diccionario["categoria"],
            datos=diccionario["data"],
            timestamp=timestamp_parseado,
        )



class GeneradorReportes:
    """
    Qué hace:
        Genera reportes a partir de los hallazgos recolectados por los módulos.
    """

    def __init__(
        self, url_objetivo: str
    ) -> None:
        """
        Qué hace:
            Inicializa el generador de reportes para una URL objetivo.

        Argumentos:
            - url_objetivo: URL objetivo del escaneo

        Atributos de instancia creados:
            - self.url_objetivo: Almacena la URL objetivo.
            - self.hallazgos: Lista vacía donde se irán agregando los hallazgos.
            - self.timestamp_inicio: Guarda el momento de inicio del escaneo.
            - self.timestamp_fin: Guarda el momento de finalización del escaneo.
            - self.metadatos: Diccionario con información del escaneo.
        """

        self.url_objetivo = url_objetivo
        self.hallazgos: List[Hallazgo] = []
        self.timestamp_inicio = datetime.now()
        self.timestamp_fin: Optional[datetime] = None
        self.metadatos: Dict[str, Any] = {
            "herramienta": NOMBRE_PROYECTO,
            "version": VERSION,
            "objetivo": url_objetivo,
        }
        
        logger.info(f"SODA       | GeneradorReportes inicializado para: {url_objetivo}")



    def cargar_reporte_existente(
        self, filepath: str
    ) -> bool:
        """
        Qué hace:
            Carga un reporte JSON existente y fusiona con los datos actuales.
            Permite persistencia incremental: si ya existe un reporte para
            el dominio, los hallazgos previos se preservan.

        Argumentos:
            - filepath: Ruta al archivo JSON existente.

        Variables:
            - ruta_reporte_existente: Objeto Path para manipular la ruta.
            - archivo: Handle del archivo abierto.
            - datos_existentes: Contenido parseado del JSON.
            - hallazgos_existentes: Lista de hallazgos del JSON.
            - metadatos_existentes: Metadatos del JSON.

        Retorna:
            True si se cargó correctamente, False si no existía o hubo error.
        """
        
        ruta_reporte_existente = Path(filepath)
        
        #Se verifica si existe un reporte previo
        if not ruta_reporte_existente.exists():
            logger.debug(f"No existe reporte previo en: {filepath}")
            return False
        
        try:
            with open(ruta_reporte_existente, "r", encoding="utf-8") as archivo:
                datos_existentes = json.load(archivo)
            
            #Se obtienen los hallazgos ya existentes y se fusionan con los hallazgos de la ejecución actual
            hallazgos_existentes = datos_existentes.get("hallazgos", [])
            self.fusionar_hallazgos(hallazgos_existentes)
            
            return True
        
        #Se manejan los errores de decodificación JSON
        except json.JSONDecodeError as error:
            logger.error(f"Error parseando JSON existente: {error}")
            return False

        #Se manejan otros errores
        except Exception as error:
            logger.error(f"Error cargando reporte existente: {error}")
            return False



    def añadir_hallazgo(
        self,
        nombre_modulo: str,
        categoria: str,
        datos: Dict[str, Any],
    ) -> None:
        """
        Qué hace:
            Agrega o actualiza un hallazgo en el reporte.
            Si ya existe un hallazgo del mismo módulo+categoría, lo reemplaza
            con el nuevo, evitando así duplicados en el reporte.

        Argumentos:
            - nombre_modulo: Nombre del módulo que reporta el hallazgo.
            - categoria: Categoría del escaneo.
            - datos: Diccionario con los datos del hallazgo.

        Variables:
            - nuevo_hallazgo: Objeto Hallazgo creado con los datos recibidos.
            - indice_existente: Posición del hallazgo existente (si lo hay).
            - indice: Variable del bucle para recorrer la lista.
            - hallazgos: Lista de hallazgos del reporte.
        """
        
        #Se crea el nuevo hallazgo
        nuevo_hallazgo = Hallazgo(nombre_modulo, categoria, datos)
        
        #Se busca si ya existe un hallazgo del mismo módulo+categoría
        indice_existente = None
        for indice in range(len(self.hallazgos)):
            hallazgo = self.hallazgos[indice]
            if hallazgo.nombre_modulo == nombre_modulo and hallazgo.categoria == categoria:
                indice_existente = indice
                break
        
        #Se decide si actualizar o añadir
        if indice_existente is not None:
            self.hallazgos[indice_existente] = nuevo_hallazgo
            logger.debug(f"Hallazgo actualizado: {nombre_modulo} ({categoria})")
        else:
            self.hallazgos.append(nuevo_hallazgo)
            logger.debug(f"Hallazgo agregado: {nombre_modulo} ({categoria})")



    def obtener_hallazgos_por_categoria(
        self, categoria: str
    ) -> List[Hallazgo]:
        """
        Qué hace:
            Obtiene todos los hallazgos de una categoría específica.

        Argumentos:
            - categoria: Categoría a filtrar (map/passive/active).

        Variables:
            - resultado: Lista con los hallazgos filtrados.
            - hallazgo: Cada hallazgo durante la iteración.

        Retorna:
            Lista de objetos Hallazgo de la categoría especificada.
        """
        
        #Se filtran los hallazgos por categoría
        resultado = []
        for hallazgo in self.hallazgos:
            if hallazgo.categoria == categoria:
                resultado.append(hallazgo)
        
        return resultado



    def fusionar_hallazgos(
        self, hallazgos_existentes: List[Dict[str, Any]]
    ) -> None:
        """
        Qué hace:
            Fusiona hallazgos existentes con los actuales.
            Para cada módulo+categoría, solo conserva el más reciente.
            Los módulos que no están en la ejecución actual se preservan.

        Argumentos:
            - hallazgos_existentes: Lista de diccionarios de hallazgos a fusionar.

        Variables:
            - modulos_actuales: Conjunto de tuplas (módulo, categoría) ya presentes.
            - datos_hallazgo: Cada diccionario de hallazgo en la iteración.
            - clave_hallazgo: Tupla (módulo, categoría) para identificar.
            - hallazgo: Objeto Hallazgo creado desde el diccionario.
        """
        
        #Se crea un set con los módulos+categorías que ya tenemos
        #Se usa un set porque permite una búsqueda más rápida que en una lista
        modulos_actuales = set()
        for hallazgo in self.hallazgos:
            clave = (hallazgo.nombre_modulo, hallazgo.categoria)
            modulos_actuales.add(clave)
        
        #Se recorren los hallazgos actuales 
        for datos_hallazgo in hallazgos_existentes:
            clave_hallazgo = (datos_hallazgo["module"], datos_hallazgo["categoria"])
            
            #Si el hallazgo es de un módulo+categoría que no está en la ejecución actual, se añade
            if clave_hallazgo not in modulos_actuales:
                hallazgo = Hallazgo.from_dict(datos_hallazgo) #Para esto se usa el decorador @dataclass
                self.hallazgos.append(hallazgo)
                modulos_actuales.add(clave_hallazgo)



    def to_dict(self) -> Dict[str, Any]:
        """
        Qué hace:
            Convierte el reporte completo a un diccionario para poder serializar a JSON.

        Variables:
            - lista_hallazgos: Lista de hallazgos convertidos a diccionarios.

        Retorna:
            Diccionario con metadatos y todos los hallazgos.
        """
        
        #Se convierten todos los hallazgos a diccionarios
        lista_hallazgos = []
        for hallazgo in self.hallazgos:
            lista_hallazgos.append(hallazgo.to_dict())
        
        return {
            "metadatos": self.metadatos,
            "hallazgos": lista_hallazgos,
        }



    def exportar_json(
        self, filepath: str
    ) -> None:
        """
        Qué hace:
            Exporta el reporte a un archivo JSON y calcula las estadísticas finales del escaneo.

        Argumentos:
            - filepath: Ruta del archivo de salida.

        Variables:
            - duracion: Tiempo total del escaneo en segundos.
            - ruta_salida: Objeto Path para manipular la ruta.
            - archivo: Handle del archivo abierto para escritura.
        """
        
        #Se registra el momento de finalización y se calcula la duración del escaneo
        self.timestamp_fin = datetime.now()
        duracion = (self.timestamp_fin - self.timestamp_inicio).total_seconds()
        
        #Se actualizan los metadatos con la información de finalización
        self.metadatos["scan_duration_seconds"] = duracion
        self.metadatos["scan_completed"] = self.timestamp_fin.isoformat()
        
        logger.info(f"SODA       | Escaneo finalizado en {duracion:.2f}s")

        
        #Se crea el directorio padre si no existe ya
        ruta_salida = Path(filepath)
        ruta_salida.parent.mkdir(parents=True, exist_ok=True)
        
        #Se escribe el archivo JSON
        with open(ruta_salida, "w", encoding="utf-8") as archivo:
            json.dump(
                self.to_dict(),
                archivo,
                indent=2,
                ensure_ascii=False
            )
        
        logger.info(f"SODA       | Reporte JSON exportado: {ruta_salida}")

