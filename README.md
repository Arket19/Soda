## Instalación

### Con pip

```bash
#Clonar el repositorio 
git clone https://github.com/Arket19/Soda.git
cd Soda

#Crear entorno virtual
python3 -m venv soda_venv
source soda_venv/bin/activate  #Linux/macOS
soda_venv\Scripts\activate     #Windows

#Instalar dependencias
pip install -r requirements.txt

#Ejecutar un escaneo
python3 soda.py -u <URL> [opciones]

#Ejemplo de uso
python3 soda.py -u ginandjuice.shop --passive --active --proxy http://127.0.0.1:8080 
```

## Con Docker

```bash
#Clonar el repositorio
git clone https://github.com/Arket19/Soda.git
cd Soda

#Construir la imagen
docker build -t soda .

#Ejecutar un escaneo
docker run --rm --network host -e PYTHONUNBUFFERED=1 -v "$(pwd):/app" soda [options]

#Ejemplo de uso
docker run --rm --network host -e PYTHONUNBUFFERED=1 -v "$(pwd):/app" soda -u ginandjuice.shop --passive --active --proxy http://127.0.0.1:8080 

```

## Evidencias de ejecución

### Módulos pasivos

#### DNS y WHOIS

Reconocimiento DNS y WHOIS con Soda ejecutado contra owasp.org:

<p align="center">
  <img src="Evidencias/Módulos pasivos/dns_whois/soda_dns_whois.png" alt="Reporte DNS y WHOIS de SODA" width="800">
</p>

Comparación con herramientas externas — nslookup y consulta WHOIS directa:

<p align="center">
  <img src="Evidencias/Módulos pasivos/dns_whois/dns1.png" alt="nslookup parte 1" width="400">
  <img src="Evidencias/Módulos pasivos/dns_whois/dns2.png" alt="nslookup parte 2" width="400">
</p>

<p align="center">
  <img src="Evidencias/Módulos pasivos/dns_whois/whois.png" alt="WHOIS externo" width="500">
</p>

#### Análisis de cabeceras HTTP

Análisis de cabeceras de seguridad basado en las recomendaciones de OWASP Secure Headers Project. Identifica cabeceras presentes, su valor y si su configuración es segura, además de listar las cabeceras faltantes:

<p align="center">
  <img src="Evidencias/Módulos pasivos/headers/soda_headers.png" alt="Reporte de cabeceras HTTP" width="700">
</p>

Comparación con Security Headers (securityheaders.com):

<p align="center">
  <img src="Evidencias/Módulos pasivos/headers/securityheaders.png" alt="Security Headers externo" width="700">
</p>

### Módulos activos

#### Detección de WAF

Detección de WAF por Soda mediante análisis pasivo de cabeceras/cookies y pruebas activas con payloads SQLi/XSS:

<p align="center">
  <img src="Evidencias/Detección de WAF/soda_waf.png" alt="Reporte detección WAF" width="700">
</p>

Verificación con Burp Suite: la respuesta del servidor confirma la presencia de PRISMA WAF:

<p align="center">
  <img src="Evidencias/Detección de WAF/waf_burpsuite.png" alt="WAF verificado con Burp Suite" width="700">
</p>

### Módulos de mapeo

#### Crawler

Ejecución del crawler sobre un sitio de pruebas local, descubriendo URLs por seguimiento de enlaces:

<p align="center">
  <img src="Evidencias/Módulos de mapeo/Crawler/soda_crawler.png" alt="Ejecución del crawler" width="800">
</p>

Generación automática del diagrama Draw.io con el visualizer:

<p align="center">
  <img src="Evidencias/Módulos de mapeo/Crawler/crawler_visualizer.png" alt="Visualizer con crawler" width="800">
</p>

Diagrama resultante abierto en Draw.io:

<p align="center">
  <img src="Evidencias/Módulos de mapeo/Crawler/crawler_drawio.png" alt="Diagrama Draw.io del crawler" width="800">
</p>

#### Discoverer

Ejecución del discoverer, que descubre la estructura web expandiendo directorios nivel por nivel:

<p align="center">
  <img src="Evidencias/Módulos de mapeo/Discoverer/soda_discoverer.png" alt="Ejecución del discoverer" width="800">
</p>

Generación automática del diagrama Draw.io con el visualizer:

<p align="center">
  <img src="Evidencias/Módulos de mapeo/Discoverer/discoverer_visualizer.png" alt="Visualizer con discoverer" width="800">
</p>

Diagrama resultante abierto en Draw.io:

<p align="center">
  <img src="Evidencias/Módulos de mapeo/Discoverer/discoverer_draw.png" alt="Diagrama Draw.io del discoverer" width="800">
</p>

### Resultados: Crawler vs Discoverer

En la carpeta [`Evidencias/Resultados_crawler_vs_discoverer/`](Evidencias/Resultados_crawler_vs_discoverer/) se encuentran los reportes completos (JSON y HTML) generados por ambos módulos sobre el mismo sitio de pruebas, permitiendo comparar los resultados de cada enfoque.

## Disclaimer
Este proyecto ha sido desarrollado con fines educativos. Se ruega que su uso se limite a entornos de prueba y auditorías con autorización previa.
