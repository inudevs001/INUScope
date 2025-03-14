# INUScope 🕵️‍♂️

**INUScope** es una herramienta básica y con una interfaz interactiva hecha en Python para escanear y enumerar subdominios de manera ética. Usa APIs como **SecurityTrails** y **VirusTotal**, y detecta subdominios activos (HTTP/HTTPS), cualquier. 🚀

## Características: ✨
- **Enumeración de subdominios** con APIs.
- **Detección de subdominios activos** (HTTP/HTTPS).
- **Multi-hilos** con control de workers.
- **Salida en texto** con detalles (URL, estado, servidor).

## Requisitos: 📋
- **Python 3.7 o superior**.
- Dependencias instaladas (ver más abajo).

## Instalación: 🛠️
```bash
1. Clona el repositorio:
   git clone https://github.com/inudevs001/INUScoop.git
   cd INUScope

2. Instala las dependencias:
   pip install -r requirements.txt
```

# Uso: 🚀
```bash
Ejecuta el script con:
python inuscoop.py
```

# Interfaz: 🎉
```bash
- `dominio`: Dominio objetivo (requerido).
- `output`: Archivo de salida (por defecto: `subdominios_encontrados.txt`).
- `timeout`: Tiempo de espera en segundos (por defecto: 2).
- `help`: Te redirige a la ayuda (muestra más detalles).
```

Ejemplos: 💡
```bash
1. Escanear un dominio:
   python inuscoop.py
   seleccionar

2. Especificar archivo de salida:
   puedes ponerle nombre al archivo donde irán los resultados

3. Usar timeout personalizado:
   puedes seleccionar el tiempo para personalizar mejor tu escaneo

# Archivo de Salida: 📄
• El script genera un archivo de texto con los subdominios encontrados. Cada línea contiene:
http://subdominio.ejemplo.com - Status: 200, Server: nginx
```

# Compatibilidad ✔️
```bash
- Sistemas Operativos: Windows, Linux, macOS.
- Python: Versión 3.7 o superior.
```

# Dependencias: 📦
```bash
Las dependencias están en `requirements.txt`:
httpx==0.24.0
requests==2.31.0
tqdm==4.66.1
rich==13.6.0
python-dotenv==1.0.0
concurrent-log-handler==0.9.23
```

# Licencia: 📜

Este proyecto está bajo la licencia *GNU GENERAL PUBLIC LICENSE v3*.
Para más detalles, consulta el archivo [LICENSE](LICENSE).

___

Creado por InuDevs ❤️ Recuerda si quieres aportar, contactame.
