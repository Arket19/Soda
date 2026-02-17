"""
Inicialización del paquete de módulos pasivos.

Funcionalidades:
    - Expone las clases principales para su importación desde otros módulos.

Módulos incluidos:
    - dns_whois: Reconocimiento DNS y WHOIS del dominio objetivo.
    - headers: Análisis de cabeceras de seguridad HTTP.
"""

from modules.passive.dns_whois import DNSRecon
from modules.passive.headers import HeadersAnalyzer
from modules.passive.tech_stack import TechStack

#Se define la lista de clases exportables del paquete
__all__ = ["DNSRecon", "HeadersAnalyzer", "TechStack"]
