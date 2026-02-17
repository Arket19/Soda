"""
Inicialización del paquete de módulos activos.

Funcionalidades:
    - Expone las clases principales para su importación desde otros módulos.

Módulos incluidos:
    - waf_detect: Detección de Web Application Firewalls.
"""

from modules.active.waf_detect import WAFDetect


#Se define la lista de clases exportables del paquete
__all__ = [
    "WAFDetect",
]
