"""
Este módulo genera reportes HTML visuales a partir de los datos de GeneradorReportes. 

Funcionalidades:
    - Generación de informe HTML a partir de plantillas Jinja2.
"""

import json

from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from jinja2 import Environment
from loguru import logger
from core import NOMBRE_PROYECTO, VERSION
from core.report_gen import GeneradorReportes
from urllib.parse import urlparse


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ project_name }} - Reporte: {{ domain }}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-purple: #a371f7;
            --border-color: #30363d;
            --shadow: 0 8px 24px rgba(0,0,0,0.4);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
        }
        
        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 2rem;
            margin-top: 1rem;
            color: var(--text-secondary);
        }
        
        .header-meta span {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0;
        }
        
        .tab-btn {
            padding: 0.75rem 1.5rem;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 1rem;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }
        
        .tab-btn:hover {
            color: var(--text-primary);
        }
        
        .tab-btn.active {
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Cards */
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .card h3 {
            color: var(--accent-blue);
            margin-bottom: 1rem;
            font-size: 1.1rem;
        }
        
        /* Tables */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        .data-table th,
        .data-table td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .data-table th {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        
        .data-table tr:hover {
            background: rgba(88, 166, 255, 0.05);
        }
        
        /* URL Lists */
        .url-list {
            list-style: none;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .url-list li {
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
            font-family: monospace;
            font-size: 0.85rem;
            word-break: break-all;
        }
        
        .url-list li:last-child {
            border-bottom: none;
        }
        
        .depth-label {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            background: var(--accent-purple);
            color: white;
            border-radius: 4px;
            font-size: 0.7rem;
            margin-right: 0.5rem;
        }
        
        /* Code blocks */
        .code-block {
            background: var(--bg-tertiary);
            border-radius: 6px;
            padding: 1rem;
            font-family: 'Fira Code', 'Consolas', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--text-secondary);
        }
        
        /* Stats grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent-blue);
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        
        /* Collapsible sections */
        .collapsible {
            cursor: pointer;
            user-select: none;
        }
        
        .collapsible::before {
            content: "▶ ";
            display: inline-block;
            transition: transform 0.2s;
        }
        
        .collapsible.open::before {
            transform: rotate(90deg);
        }
        
        .collapsible-content {
            display: none;
            padding-top: 1rem;
        }
        
        .collapsible-content.open {
            display: block;
        }
        
        /* Technology badges */
        .tech-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            font-size: 0.8rem;
            margin: 0.25rem;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <h1>SODA</h1>
            <p style="color: var(--text-secondary);">Herramienta de Reconocimiento Web</p>
            <div class="header-meta">
                <span>🎯 <a href="{{ url_objetivo }}" target="_blank" style="color: var(--text-primary); text-decoration: none;"><strong>{{ domain }}</strong></a></span>
                <span>📅 {{ scan_date }}</span>
                <span>🔧 v{{ version }}</span>
            </div>
        </header>
        
        <!-- Tabs Navigation: solo Pasivo y Activo (mapeo va dentro de Activo) -->
        <div class="tabs">
            {% if passive_findings %}
            <button class="tab-btn active" onclick="showTab('passive')">Pasivo</button>
            {% endif %}
            {% if active_findings or map_data %}
            <button class="tab-btn {% if not passive_findings %}active{% endif %}" onclick="showTab('active')">Activo</button>
            {% endif %}
        </div>

        <!-- PASSIVE Tab: siempre es la pestaña activa por defecto si tiene contenido -->
        {% if passive_findings %}
        <div id="tab-passive" class="tab-content active">
            {% for finding in passive_findings %}
            
            {% if finding.module == 'headers_analyzer' %}
            <div class="card">
                <h3>🔒 Análisis de Headers HTTP</h3>
                
                {% if finding.data.cabeceras_seguras.presentes %}
                <h4 style="margin: 1rem 0 0.5rem; color: var(--accent-green);">✓ Headers de Seguridad Presentes</h4>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Valor</th>
                            <th>Seguro</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for header, info in finding.data.cabeceras_seguras.presentes.items() %}
                        <tr>
                            <td><code>{{ header }}</code></td>
                            <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">{{ info.valor[:100] }}{% if info.valor | length > 100 %}...{% endif %}</td>
                            <td>{% if info.seguro %}✅{% else %}⚠️{% endif %}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
                
                {% if finding.data.cabeceras_seguras.ausentes %}
                <h4 style="margin: 1.5rem 0 0.5rem; color: var(--accent-yellow);">⚠ Headers Faltantes</h4>
                <ul class="url-list">
                    {% for header in finding.data.cabeceras_seguras.ausentes %}
                    <li>{{ header }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                {% if finding.data.cabeceras_eliminables %}
                <h4 style="margin: 1.5rem 0 0.5rem; color: var(--accent-purple);">🔎 Headers Reveladores (eliminar)</h4>
                <table class="data-table">
                    <tbody>
                        {% for key, value in finding.data.cabeceras_eliminables.items() %}
                        <tr>
                            <td><strong>{{ key }}</strong></td>
                            <td>{{ value }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
                
                {% if finding.data.recomendaciones %}
                <h4 style="margin: 1.5rem 0 0.5rem;">📋 Recomendaciones</h4>
                <ul class="url-list">
                    {% for recomendacion in finding.data.recomendaciones %}
                    <li>{{ recomendacion }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endif %}
            
            {% if finding.module == 'DNS_WHOIS' %}
            <div class="card">
                <h3>🌐 Reconocimiento DNS y WHOIS</h3>
                
                {% if finding.data.hallazgos_dns %}
                <h4 style="margin: 1rem 0 0.5rem; color: var(--accent-blue);">📡 Registros DNS</h4>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Tipo</th>
                            <th>Registros</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for record_type, records in finding.data.hallazgos_dns.items() %}
                        <tr>
                            <td><strong>{{ record_type }}</strong></td>
                            <td>{{ records | join(', ') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
                
                {% if finding.data.hallazgos_whois %}
                <h4 style="margin: 1.5rem 0 0.5rem; color: var(--accent-purple);">📋 Información WHOIS</h4>
                <table class="data-table">
                    <tbody>
                        {% for key, value in finding.data.hallazgos_whois.items() %}
                        <tr>
                            <td><strong>{{ key | replace('_', ' ') | title }}</strong></td>
                            <td>{{ value if value is string else value | join(', ') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
            </div>
            {% endif %}
            
            {% if finding.module == 'tech_stack' %}
            <div class="card">
                <h3>🛠️ Identificación de Tecnologías</h3>
                <div style="background: var(--bg-tertiary); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem;">
                    <p style="margin-bottom: 1rem;">{{ finding.data.recomendacion }}</p>
                    <p style="margin-bottom: 1rem;">
                        <strong>URL objetivo:</strong> 
                        <a href="{{ finding.data.url_objetivo }}" target="_blank" style="color: var(--accent-blue);">{{ finding.data.url_objetivo }}</a>
                    </p>
                    <p>
                        <a href="{{ finding.data.url_wappalyzer }}" target="_blank" 
                           style="display: inline-block; padding: 0.5rem 1rem; background: var(--accent-green); color: #000; border-radius: 6px; text-decoration: none; font-weight: bold;">
                            🔗 Instalar Wappalyzer
                        </a>
                    </p>
                </div>
                
                {% if finding.data.instrucciones %}
                <h4 style="margin: 1rem 0 0.5rem;">📝 Instrucciones</h4>
                <ul class="url-list">
                    {% for instruccion in finding.data.instrucciones %}
                    <li>{{ instruccion }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
            </div>
            {% endif %}
            
            {% endfor %}
        </div>
        {% endif %}
        
        <!-- ACTIVE Tab: incluye WAF, fuzzer y modulos de mapeo -->
        {% if active_findings or map_data %}
        <div id="tab-active" class="tab-content {% if not passive_findings %}active{% endif %}">

            <!-- Seccion de mapeo: estadisticas, subdominios, robots, sitemaps, parametros -->
            {% if map_data %}

            <!-- Estadisticas del crawler (si corrió) -->
            {% if map_data.crawler %}
            <div class="card">
                <h3>🕷️ Crawler</h3>
                <div class="stats-grid" style="margin-bottom: 0;">
                    <div class="stat-card">
                        <div class="stat-value">{{ map_data.crawler.urls_discovered | default(0) }}</div>
                        <div class="stat-label">URLs Descubiertas</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ map_data.subdomains | length }}</div>
                        <div class="stat-label">Subdominios</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ map_data.crawler.max_depth | default(0) }}</div>
                        <div class="stat-label">Profundidad Máxima</div>
                    </div>
                </div>
            </div>
            {% endif %}

            <!-- Estadisticas del discoverer (si corrió) -->
            {% if map_data.discoverer %}
            <div class="card">
                <h3>🔎 Discoverer</h3>
                <div class="stats-grid" style="margin-bottom: 0;">
                    <div class="stat-card">
                        <div class="stat-value">{{ map_data.discoverer.urls_discovered | default(0) }}</div>
                        <div class="stat-label">URLs Descubiertas</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ map_data.subdomains | length }}</div>
                        <div class="stat-label">Subdominios</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{{ map_data.discoverer.max_depth | default(0) }}</div>
                        <div class="stat-label">Profundidad Máxima</div>
                    </div>
                    {% if map_data.discoverer.urls_truncadas %}
                    <div class="stat-card">
                        <div class="stat-value">{{ map_data.discoverer.urls_truncadas | length }}</div>
                        <div class="stat-label">Directorios Truncados</div>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endif %}

            {% if map_data.subdomains %}
            <div class="card">
                <h3>🌐 Subdominios Detectados</h3>
                <ul class="url-list">
                    {% for subdomain in map_data.subdomains %}
                    <li>{{ subdomain }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}

            {% if map_data.get_params %}
            <div class="card">
                <h3>🔗 Parámetros GET Detectados</h3>
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">Puntos potenciales de inyección (SQL, XSS, IDOR, etc.)</p>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Parámetro</th>
                            <th>Valores de ejemplo</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for param, values in map_data.get_params.items() %}
                        <tr>
                            <td><code>{{ param }}</code></td>
                            <td>{{ values | join(', ') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            {% if map_data.robots_txt %}
            <div class="card">
                <h3>🤖 robots.txt</h3>
                <p style="color: var(--text-secondary);">{{ map_data.robots_txt }}</p>
            </div>
            {% endif %}

            {% if map_data.sitemap %}
            <div class="card">
                <h3>🗺️ Sitemaps</h3>
                <ul class="url-list">
                    {% for sitemap_url in map_data.sitemap %}
                    <li>{{ sitemap_url }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}

            {% if map_data.exclude_paths %}
            <div class="card">
                <h3>🚫 Paths Excluidos</h3>
                <div class="code-block">{{ map_data.exclude_paths | join(', ') }}</div>
            </div>
            {% endif %}

            <!-- Diagrama del visualizador -->
            {% if map_data.visualizer %}
            <div class="card">
                <h3>📊 Diagrama de Estructura Web</h3>
                {% if map_data.visualizer.drawio_json %}
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                    ✅ Diagrama generado — <code>{{ map_data.visualizer.archivo_drawio }}</code>
                </p>
                <div class="mxgraph" style="max-width:100%; border:1px solid var(--border-color); border-radius:8px; overflow:hidden; background:#ffffff;" data-mxgraph="{{ map_data.visualizer.drawio_json | e }}"></div>
                <script type="text/javascript" src="https://viewer.diagrams.net/js/viewer-static.min.js"></script>
                {% elif map_data.visualizer.modo == 'automatico' %}
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                    ✅ Diagrama generado correctamente
                </p>
                <div style="background: linear-gradient(135deg, #1a472a 0%, #2d5a3d 100%); border-radius: 8px; padding: 2rem; text-align: center; border: 1px solid var(--accent-green);">
                    <p style="font-size: 4rem; margin-bottom: 1rem;">🗺️</p>
                    <p style="font-size: 1.2rem; font-weight: bold; margin-bottom: 0.5rem;">{{ map_data.visualizer.archivo_generado }}</p>
                    <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                        El mapa del sitio está listo para visualizar
                    </p>
                    <a href="https://app.diagrams.net/"
                       target="_blank"
                       style="display: inline-block; padding: 0.75rem 2rem; background: var(--accent-green); color: #000; border-radius: 6px; text-decoration: none; font-weight: bold;">
                        🔗 Abrir en Draw.io
                    </a>
                    <p style="color: var(--text-secondary); margin-top: 1rem; font-size: 0.85rem;">
                        Arrastra el archivo .drawio a la aplicación para visualizarlo
                    </p>
                </div>
                {% else %}
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                    ⏳ Se ha generado un archivo con las rutas y el prompt para crear el diagrama manualmente.
                </p>
                <div style="background: var(--bg-tertiary); border-radius: 8px; padding: 2rem; text-align: center;">
                    <p style="font-size: 3rem; margin-bottom: 1rem;">🗺️</p>
                    <p><strong>{{ map_data.visualizer.archivo_generado }}</strong></p>
                    <p style="color: var(--text-secondary); margin-top: 1rem;">
                        1. Copia el contenido del archivo y pégalo en un LLM (ChatGPT, Claude, etc.)
                    </p>
                    <p style="color: var(--text-secondary); margin-top: 0.5rem;">
                        2. Guarda la respuesta del LLM en: <code>{{ map_data.visualizer.archivo_drawio }}</code>
                    </p>
                    <p style="color: var(--text-secondary); margin-top: 0.5rem;">
                        3. Ábrelo con <a href="https://app.diagrams.net/" target="_blank" style="color: var(--accent-blue);">Draw.io</a> o regenera el informe con <code>--report-update</code> para verlo aquí
                    </p>
                </div>
                {% endif %}
            </div>
            {% endif %}

            {% endif %}

            <!-- WAF y otros modulos activos -->
            {% for finding in active_findings %}

            {% if finding.module == 'waf_detector' %}
            <div class="card">
                <h3>🛡️ Detección de WAF</h3>
                <table class="data-table">
                    <tbody>
                        {% if finding.data.waf_detected %}
                        <tr>
                            <td><strong>Estado</strong></td>
                            <td>WAF detectado</td>
                        </tr>
                        <tr>
                            <td><strong>Modelo</strong></td>
                            <td>{% if finding.data.waf_name and finding.data.waf_name != 'Desconocido' %}{{ finding.data.waf_name }}{% else %}Modelo desconocido{% endif %}</td>
                        </tr>
                        {% if finding.data.indicators %}
                        <tr>
                            <td><strong>Indicadores</strong></td>
                            <td>{{ finding.data.indicators | join(', ') }}</td>
                        </tr>
                        {% endif %}
                        {% else %}
                        <tr>
                            <td><strong>Estado</strong></td>
                            <td>WAF no detectado</td>
                        </tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            {% if finding.module == 'fuzzer' %}
            <div class="card">
                <h3>📂 Resultados de Fuzzing</h3>
                {% if finding.data.discovered_paths %}
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Content-Length</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for path in finding.data.discovered_paths %}
                        <tr>
                            <td><code>{{ path.path }}</code></td>
                            <td>{{ path.status }}</td>
                            <td>{{ path.content_length | default('-') }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">No se encontraron paths adicionales</div>
                {% endif %}
            </div>
            {% endif %}

            {% endfor %}
        </div>
        {% endif %}
        
        <!-- Footer -->
        <footer class="footer">
            <p>SODA • v{{ version }} • {{ generation_time }}</p>
        </footer>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById('tab-' + tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        function toggleCollapsible(element) {
            element.classList.toggle('open');
            element.nextElementSibling.classList.toggle('open');
        }
    </script>
</body>
</html>
'''



class GeneradorReporteHTML:
    """
    Qué hace:
        Genera reportes HTML usando Jinja2 como motor de plantillas
        a partir de los datos de GeneradorReportes.
    """

    def __init__(self, reporte: GeneradorReportes) -> None:
        """
        Qué hace:
            Inicializa el generador HTML con el reporte a visualizar.

        Argumentos:
            - reporte: Objeto GeneradorReportes con los datos a mostrar.

        Atributos de instancia creados:
            - self.reporte: Almacena la referencia al objeto GeneradorReportes.
            - self.entorno: Entorno Jinja2 con carga desde string.
            - self.plantilla: Template compilado desde HTML_TEMPLATE.
        """
        
        #Se almacena el reporte para acceder a los hallazgos
        self.reporte = reporte
        
        #Se crea el entorno de Jinja2 y se carga la plantilla
        self.entorno = Environment()
        self.plantilla = self.entorno.from_string(HTML_TEMPLATE)
        
        logger.debug("GeneradorReporteHTML inicializado")



    def _preparar_datos_plantilla(self) -> Dict[str, Any]:
        """
        Qué hace:
            Construye el diccionario con los datos del escaneo para rellenar la plantilla Jinja2.

        Variables:
            - url_parseada: Guarda los distintos componentes de la URL
            - dominio: Nombre del dominio extraído de la URL.
            - hallazgos_map: Lista de hallazgos de la categoría "map".
            - hallazgos_pasivos: Lista de hallazgos de la categoría "passive".
            - hallazgos_activos: Lista de hallazgos de la categoría "active".

        Retorna:
            Diccionario con todas las variables para la plantilla.
        """
        
        #Se extrae el dominio de la URL objetivo
        url_parseada = urlparse(self.reporte.url_objetivo)
        dominio = url_parseada.netloc or self.reporte.url_objetivo
        

        #Se obtienen los hallazgos de cada categoría
        hallazgos_map_raw = self.reporte.obtener_hallazgos_por_categoria("map")

        hallazgos_pasivos = []
        for hallazgo in self.reporte.obtener_hallazgos_por_categoria("passive"):
            hallazgos_pasivos.append(hallazgo.to_dict())

        hallazgos_activos = []
        for hallazgo in self.reporte.obtener_hallazgos_por_categoria("active"):
            hallazgos_activos.append(hallazgo.to_dict())


        # Se construye el diccionario unificado con los resultados de crawler y/o discoverer
        map_data = None

        datos_crawler = None
        datos_discoverer = None
        datos_visualizer = None

        for hallazgo in hallazgos_map_raw:
            if hallazgo.nombre_modulo == "crawler":
                datos_crawler = hallazgo.datos
            elif hallazgo.nombre_modulo == "discoverer":
                datos_discoverer = hallazgo.datos
            elif hallazgo.nombre_modulo == "visualizer":
                datos_visualizer = hallazgo.datos

        #Se toma como base las rutas encontradas por el crawler
        datos_base = datos_crawler if datos_crawler else datos_discoverer

        if datos_base:
            #Se unifican subdominios de ambos módulos eliminando duplicados
            subdominios_crawler = set(datos_crawler.get("subdomains", [])) if datos_crawler else set()
            subdominios_discoverer = set(datos_discoverer.get("subdomains", [])) if datos_discoverer else set()
            subdominios_unificados = sorted(subdominios_crawler | subdominios_discoverer)

            #Se unifican sitemaps de ambos módulos eliminando duplicados
            sitemaps_crawler = datos_crawler.get("sitemap", []) if datos_crawler else []
            sitemaps_discoverer = datos_discoverer.get("sitemap", []) if datos_discoverer else []
            sitemaps_unificados = sorted(set(sitemaps_crawler + sitemaps_discoverer))

            #Se coge robots_txt del que lo tenga
            robots_txt = datos_base.get("robots_txt")

            #Se cogen los parámetros y rutas excluidas del módulo que los tenga
            get_params_raw = datos_base.get("get_params", {})
            exclude_paths = datos_base.get("exclude_paths", [])

            #Se transforman los parámetros para que la salida sea legible
            get_params = {}
            for nombre_param, pares_valor_ruta in get_params_raw.items():
                valores_por_ruta = {}
                for par in pares_valor_ruta:
                    valor = par[0]
                    ruta = par[1] if len(par) > 1 else "/"
                    if ruta not in valores_por_ruta:
                        valores_por_ruta[ruta] = []
                    if valor not in valores_por_ruta[ruta]:
                        valores_por_ruta[ruta].append(valor)

                for ruta, valores in valores_por_ruta.items():
                    clave_display = f"{ruta}?{nombre_param}"
                    get_params[clave_display] = valores

            #Se construye el sub-diccionario del crawler
            if datos_crawler:
                crawler_stats = {
                    "urls_discovered": datos_crawler.get("urls_discovered", 0),
                    "max_depth": datos_crawler.get("max_depth", 0),
                }

            #Se construye el sub-diccionario del discoverer
            discoverer_stats = None
            if datos_discoverer:
                discoverer_stats = {
                    "urls_discovered": datos_discoverer.get("urls_discovered", 0),
                    "max_depth": datos_discoverer.get("max_depth", 0),
                    "urls_truncadas": datos_discoverer.get("urls_truncadas", []),
                }

            #Se reúnen todos los datos
            map_data = {
                "crawler": crawler_stats,
                "discoverer": discoverer_stats,
                "subdomains": subdominios_unificados,
                "get_params": get_params,
                "robots_txt": robots_txt,
                "sitemap": sitemaps_unificados,
                "exclude_paths": exclude_paths,
                "visualizer": None,
            }

            #Se añaden los datos del visualizador 
            if datos_visualizer:
                #Se intenta leer el .drawio para incrustarlo en el informe
                archivo_drawio = datos_visualizer.get("archivo_drawio", "")
                if archivo_drawio:
                    ruta_drawio = Path(archivo_drawio)
                    if ruta_drawio.exists() and ruta_drawio.stat().st_size > 0:
                        contenido_xml = ruta_drawio.read_text(encoding="utf-8")
                        if "<mxfile" in contenido_xml:
                            datos_visualizer["drawio_json"] = json.dumps({
                                "highlight": "#0000ff",
                                "nav": True,
                                "resize": True,
                                "xml": contenido_xml,
                            })

                map_data["visualizer"] = datos_visualizer

        #Se retorna el diccionario con los datos para la plantilla
        return {
            "project_name": NOMBRE_PROYECTO,
            "version": VERSION,
            "domain": dominio,
            "url_objetivo": self.reporte.url_objetivo,
            "scan_date": self.reporte.timestamp_inicio.strftime("%H:%M %d/%m/%y"),
            "generation_time": datetime.now().strftime("%H:%M %d/%m/%y"),
            "map_data": map_data,
            "passive_findings": hallazgos_pasivos,
            "active_findings": hallazgos_activos,
        }



    def generate(self, ruta_salida: str) -> str:
        """
        Qué hace:
            Genera el archivo HTML del reporte.

        Argumentos:
            - ruta_salida: Ruta donde guardar el archivo HTML.

        Variables:
            - archivo_salida: Objeto Path con la ruta del archivo.
            - contenido_html: HTML generado por Jinja2.
            - archivo: Handle del archivo abierto para escritura.

        Retorna:
            Ruta absoluta del archivo generado.
        """
        
        archivo_salida = Path(ruta_salida)
        
        #Se preparan los datos para la plantilla
        datos_plantilla = self._preparar_datos_plantilla()

        #Se rellena la plantilla con los datos 
        contenido_html = self.plantilla.render(**datos_plantilla) #Se usa ** para desempaquetar el diccionario
        
        #Se escribe el archivo HTML
        with open(archivo_salida, "w", encoding="utf-8") as archivo:
            archivo.write(contenido_html)
        
        logger.info(f"Reporte HTML generado: {archivo_salida}")
        
        return str(archivo_salida.absolute())