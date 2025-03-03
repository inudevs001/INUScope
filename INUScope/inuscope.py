from urllib.parse import urlparse
import socket
import requests
import logging
import time
import concurrent.futures
import httpx
from tqdm import tqdm
from rich.console import Console
import os

# Configuración de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Presentación ASCII
PRESENTACION_ASCII = r"""

$$$$$$\ $$\   $$\ $$\   $$\  $$$$$$\                                          
\_$$  _|$$$\  $$ |$$ |  $$ |$$  __$$\                                         
  $$ |  $$$$\ $$ |$$ |  $$ |$$ /  \__| $$$$$$$\  $$$$$$\   $$$$$$\   $$$$$$\  
  $$ |  $$ $$\$$ |$$ |  $$ |\$$$$$$\  $$  _____|$$  __$$\ $$  __$$\ $$  __$$\ 
  $$ |  $$ \$$$$ |$$ |  $$ | \____$$\ $$ /      $$ /  $$ |$$ /  $$ |$$$$$$$$ |
  $$ |  $$ |\$$$ |$$ |  $$ |$$\   $$ |$$ |      $$ |  $$ |$$ |  $$ |$$   ____|
$$$$$$\ $$ | \$$ |\$$$$$$  |\$$$$$$  |\$$$$$$$\ \$$$$$$  |$$$$$$$  |\$$$$$$$\ 
\______|\__|  \__| \______/  \______/  \_______| \______/ $$  ____/  \_______|
                                                          $$ |                
                                                          $$ |                
                                                          \__|                
"""

# Claves de API (¡Reemplaza con tus propias claves!)
SECURITYTRAILS_API_KEY = "COLOCA_TU_API_KEY"  # Reemplaza con tu clave de SecurityTrails
VIRUSTOTAL_API_KEY = "COLOCA_TU_API_KEY"  # Reemplaza con tu clave de VirusTotal

# Función para obtener subdominios desde SecurityTrails API
def obtener_subdominios_securitytrails(dominio):
    url = f"https://api.securitytrails.com/v1/domain/{dominio}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            subdominios = response.json().get("subdomains", [])
            logging.info(f"SecurityTrails: Se encontraron {len(subdominios)} subdominios.")
            return [f"{subdominio}.{dominio}" for subdominio in subdominios]
        elif response.status_code == 429:  # Rate limit alcanzado
            logging.warning("Límite de tasa alcanzado en SecurityTrails. Esperando 1 segundo...")
            time.sleep(1)
            return obtener_subdominios_securitytrails(dominio)  # Reintentar
        else:
            logging.error(f"Error en SecurityTrails: Código de estado {response.status_code}")
            logging.error(f"Respuesta: {response.text}")  # Mostrar la respuesta de la API
    except Exception as e:
        logging.error(f"Error al obtener subdominios desde SecurityTrails: {e}")
    return []

# Función para obtener subdominios desde VirusTotal API
def obtener_subdominios_virustotal(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}/subdomains"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            subdominios = [subdominio["id"] for subdominio in response.json().get("data", [])]
            logging.info(f"VirusTotal: Se encontraron {len(subdominios)} subdominios.")
            return subdominios
        elif response.status_code == 429:  # Rate limit alcanzado
            logging.warning("Límite de tasa alcanzado en VirusTotal. Esperando 60 segundos...")
            time.sleep(60)
            return obtener_subdominios_virustotal(dominio)  # Reintentar
        else:
            logging.error(f"Error en VirusTotal: Código de estado {response.status_code}")
            logging.error(f"Respuesta: {response.text}")  # Mostrar la respuesta de la API
    except Exception as e:
        logging.error(f"Error al obtener subdominios desde VirusTotal: {e}")
    return []

# Función para probar un subdominio
def probar_subdominio(subdominio, timeout):
    for scheme in ["http", "https"]:
        url = f"{scheme}://{subdominio}"
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.get(url)
                if response.status_code in [200, 301, 302, 403, 401]:  # Códigos de estado comunes
                    # Resolver la IP del subdominio
                    try:
                        ip = socket.gethostbyname(subdominio)
                    except socket.gaierror:
                        ip = "No resuelta"
                    return url, response.status_code, response.headers.get("Server", "Desconocido"), ip
        except (httpx.RequestError, httpx.TimeoutException) as e:
            logging.debug(f"Error al probar {url}: {e}")
    return None

# Función para limpiar la pantalla
def limpiar_pantalla():
    os.system("cls" if os.name == "nt" else "clear")

# Función para escribir resultados en formato tabular
def escribir_resultados_tabular(archivo_salida, resultados):
    with open(archivo_salida, "w") as f:
        # Encabezado
        f.write("-" * 80 + "\n")
        f.write(f"{'SUBDOMINIO':<40} | {'IP':<15} | {'ESTADO':<8} | {'SERVIDOR'}\n")
        f.write("-" * 80 + "\n")
        # Datos
        for resultado in resultados:
            url, status_code, servidor, ip = resultado
            f.write(f"{url:<40} | {ip:<15} | {status_code:<8} | {servidor}\n")
        f.write("-" * 80 + "\n")

# Función principal
def main():
    console = Console()
    limpiar_pantalla()
    console.print(PRESENTACION_ASCII, style="bold blue")
    console.print("by: inudevs\n", style="bold white")

    while True:
        console.print("\nOpciones:", style="bold yellow")
        console.print("1) help - Muestra los comandos disponibles")
        console.print("2) scan - Escanear un dominio")
        console.print("3) exit - Salir de la herramienta")

        comando = console.input("\n> ").strip().lower()

        if comando == "help" or comando == "1":
            console.print("\nComandos disponibles:", style="bold green")
            console.print("- scan: Escanear un dominio")
            console.print("- exit: Salir de la herramienta")
            console.print("\nPara más detalles, consulta el README.md.", style="bold yellow")

        elif comando == "scan" or comando == "2":
            dominio = console.input("Ingresa el dominio a escanear (ejemplo.com): ").strip()
            archivo_salida = console.input("Ingresa el nombre del archivo de salida (por ejemplo: resultados.txt): ").strip()
            if not archivo_salida:
                archivo_salida = "subdominios_encontrados.txt"  # Nombre por defecto
            timeout = int(console.input("Ingresa el timeout en segundos (por defecto: 2): ").strip() or 2)

            console.print(f"\nEscaneando {dominio}...", style="bold green")

            # Obtener subdominios desde APIs
            subdominios = []
            console.print("[bold yellow][*] Obteniendo subdominios desde SecurityTrails...")
            subdominios_st = obtener_subdominios_securitytrails(dominio)
            subdominios.extend(subdominios_st)
            console.print(f"[bold green][*] Se obtuvieron {len(subdominios_st)} subdominios desde SecurityTrails")

            console.print("[bold yellow][*] Obteniendo subdominios desde VirusTotal...")
            subdominios_vt = obtener_subdominios_virustotal(dominio)
            subdominios.extend(subdominios_vt)
            console.print(f"[bold green][*] Se obtuvieron {len(subdominios_vt)} subdominios desde VirusTotal")

            # Eliminar duplicados
            subdominios = list(set(subdominios))

            # Barra de progreso con tqdm
            console.print(f"[bold yellow][*] Probando {len(subdominios)} subdominios...")
            resultados = []
            with tqdm(total=len(subdominios), desc="Escaneando", unit="subdominio") as pbar:
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    futures = {executor.submit(probar_subdominio, subdominio, timeout): subdominio for subdominio in subdominios}

                    for future in concurrent.futures.as_completed(futures):
                        resultado = future.result()
                        if resultado:
                            resultados.append(resultado)
                        pbar.update(1)

            # Escribir resultados en formato tabular
            escribir_resultados_tabular(archivo_salida, resultados)

            # Mensaje final decorado
            limpiar_pantalla()
            console.print("[bold green]¡Escaneo completado![/bold green]")
            console.print(f"[bold yellow]Los resultados se han guardado en: [bold green]{archivo_salida}[/bold green]")
            console.print("\nPresiona cualquier tecla para continuar...", style="bold yellow")
            input()  # Esperar a que el usuario presione una tecla
            limpiar_pantalla()
            console.print(PRESENTACION_ASCII, style="bold blue")
            console.print("by: inudevs\n", style="bold white")

        elif comando == "exit" or comando == "3":
            console.print("Saliendo de INUScoop... ¡Hasta luego! c:", style="bold red")
            break

        else:
            console.print("Comando no reconocido. Escribe 'help' para ver los comandos disponibles.", style="bold red")

if __name__ == "__main__":
    main()