"""
Inicialización del paquete de módulos de mapeo.

Módulos incluidos:
    - crawler: Web crawler con técnicas anti-detección.
    - discoverer: Buscador de URLs según profundidad
    - visualizer: Generador de diagramas Draw.io.
"""

from modules.map.crawler import Crawler
from modules.map.visualizer import Visualizer
from modules.map.discoverer import Discoverer

#Se define la lista de clases exportables del paquete
__all__ = ["Crawler", "Visualizer", "Discoverer"]
