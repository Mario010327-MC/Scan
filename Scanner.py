import os, wmi
import socket
from datetime import datetime
import platform
from getpass import getuser
import subprocess
import winreg
import tempfile
import win32com.client
import psycopg2
from psycopg2 import sql, OperationalError
import json
from datetime import datetime
import socket
from concurrent.futures import ThreadPoolExecutor

def create_database_if_not_exists(db_name="scanner", user="postgres", password="123", host="localhost"):
    """Crea la base de datos solo si no existe"""
    try:
        # Conexión inicial al servidor PostgreSQL (sin especificar DB)
        conn = psycopg2.connect(
            user=user,
            password=password,
            host=host,
            dbname="postgres"  # Conexión a la DB por defecto
        )
        conn.autocommit = True  # Necesario para ejecutar CREATE DATABASE
        cursor = conn.cursor()

        # Verificar si la base de datos ya existe
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (db_name,))
        exists = cursor.fetchone()

        if not exists:
            cursor.execute(f"CREATE DATABASE {db_name};")
            print(f"✅ Base de datos '{db_name}' creada exitosamente")
        else:
            print(f"ℹ️ La base de datos '{db_name}' ya existe. Continuando...")

    except OperationalError as e:
        print(f"❌ Error de conexión a PostgreSQL: {e}")
        raise  # Relanza la excepción para manejo externo
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

DB_CONFIG = {
    "dbname": "scanner",
    "user": "postgres",
    "password": "1234",
    "host": "localhost",
    "port": "5432"
}

def create_database_structure():
    """Crea la estructura de la base de datos si no existe."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Tabla para información general del sistema
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_info (
                id SERIAL PRIMARY KEY,
                fecha_ejecucion TIMESTAMP,
                nombre_pc VARCHAR(255),
                direccion_ip VARCHAR(50),
                usuario_activo VARCHAR(100),
                escritorio_remoto VARCHAR(50),
                unido_kms VARCHAR(10),
                data_json JSONB
            )
        """)
        
        conn.commit()
        print("✅ Estructura de la base de datos creada correctamente.")
    except OperationalError as e:
        print(f"❌ Error de conexión a PostgreSQL: {e}")
    except Exception as e:
        print(f"❌ Error al crear la estructura de la base de datos: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

def send_to_postgresql(data):
    """Envía los datos recopilados a PostgreSQL."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Convertir los datos a JSON para almacenamiento flexible
        data_json = {
            "users_admin": data["users_admin"],
            "all_users": data["all_users"],
            "system_data": data["system_data"],
            "port_data": data["port_data"],
            "device_data": data["device_data"],
            "usb_ports": data["usb_ports"],
            "port_states": data["port_states"],
            "kaspersky_data": data["kaspersky_data"],
            "segurmatica_data": data["segurmatica_data"],
            "parches": data["parches"],
            "carpetas_compartidas": data["carpetas_compartidas"],
            "device_history": data["device_histoty"]
        }
        
        # Insertar datos en la base de datos
        cursor.execute("""
            INSERT INTO system_info (
                fecha_ejecucion, nombre_pc, direccion_ip, usuario_activo,
                escritorio_remoto, unido_kms, data_json
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            datetime.strptime(data["fecha"], "%Y-%m-%d %H:%M:%S"),
            data["nombre_pc"],
            data["ip_fisica"],
            data["user_active"],
            data["escritorio_remoto"],
            data["kms"],
            json.dumps(data_json)
        ))
        
        conn.commit()
        print("✅ Datos enviados correctamente a PostgreSQL.")
    except OperationalError as e:
        print(f"❌ Error de conexión a PostgreSQL: {e}")
    except Exception as e:
        print(f"❌ Error al enviar datos a PostgreSQL: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

#Comprobar el SO
system = platform.system()

#Obtener nombre de la pc
def obtener_nombre_pc():
    return socket.gethostname()

def es_interfaz_fisica(interfaz):
    nombres_excluidos = ['VMware', 'Loopback', 'vboxnet', 'vEthernet']
    for nombre in nombres_excluidos:
        if nombre in interfaz:
            return False
    return True

#Obtener DIreccion IP
def get_ip():
    system = platform.system()
    if system == "Windows":
        output = subprocess.check_output("ipconfig", universal_newlines=True)
        lines = output.split("\n")
        for line in lines:
            if "IPv4" in line or "Dirección IP" in line:
                partes = line.split(":")
                if len(partes) == 2:
                    direccion_ip = partes[1].strip()
                    return direccion_ip
    elif system == "Linux":
        try:
            output = subprocess.check_output("ifconfig", universal_newlines=True)
        except subprocess.CalledProcessError:
            output = subprocess.check_output("hostname -I", universal_newlines=True).strip()
            if output:
                return output.split()[0]
        lines = output.split("\n")
        interfaz = None
        for line in lines:
            if line:
                if not line.startswith(" "):
                    interfaz = line.split(":")[0]
                elif es_interfaz_fisica(interfaz):
                    if "inet addr" in line or "inet " in line:
                        partes = line.split()
                        for parte in partes:
                            if "addr:" in parte:
                                direccion_ip = parte.split(":")[1]
                                return direccion_ip
                            elif parte.startswith("inet"):
                                direccion_ip = parte.split()[1]
                                return direccion_ip
    return None


def get_execution_date():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_active_user():
    return getuser()

def get_all_users():
    user_list = []

    if system == 'Windows':
        try:
            output = subprocess.check_output('wmic useraccount where "disabled=0" get name', universal_newlines=True)
            lines = output.split('\n')
            for line in lines:
                username = line.strip()
                if username and username != 'Name':
                    user_list.append(username)
            return user_list
        except Exception as e:
            return ["Error al obtener la lista de usuarios en Windows: {}".format(e)]

    elif system == 'Linux':
        try:
            with open("/etc/passwd", "r") as f:
                for line in f:
                    if es_usuario_habilitado_linux(line):
                        user_list.append(line.split(":")[0])
            return user_list
        except Exception as e:
            return ["Error al obtener la lista de usuarios en Linux: {}".format(e)]

    else:
        return ["Sistema operativo no soportado"]

def es_usuario_habilitado_linux(line):
    partes = line.split(":")
    shell = partes[-1].strip()
    return shell not in ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']

def get_admin_users():
    admin_list = []

    if system == 'Windows':
        try:
            import win32net
            data = win32net.NetLocalGroupGetMembers(None, 'Administradores', 1)
            for user in data[0]:
                admin_list.append(user['name'])
            return admin_list
        except ImportError:
            return ["Error al importar win32net"]
        except Exception as e:
            return ["Error al obtener la lista de usuarios administradores en Windows: {}".format(e)]

    elif system == 'Linux':
        try:
            with open("/etc/group", "r") as f:
                for line in f:
                    # Verificar si la línea corresponde al grupo sudo o wheel
                    if line.startswith("sudo:") or line.startswith("wheel:"):
                        # El formato del archivo /etc/group es: nombre_grupo:x:ID_grupo:lista_usuarios
                        users = line.split(":")[3].strip()
                        admin_list.extend(users.split(","))
            if admin_list:
                return admin_list
            else:
                return ["No se encontraron usuarios administradores en Linux."]
        except Exception as e:
            return ["Error al obtener la lista de usuarios administradores en Linux: {}".format(e)]

    else:
        return ["Sistema operativo no soportado"]

def get_installed_apps():
    if system == "Linux":
        return get_installed_apps_linux()
    elif system == "Windows":
        return get_installed_apps_windows()
    else:
        return [], None, None

def get_installed_apps_windows():
    def _get_installed_apps_windows(hive, flag):
        try:
            aReg = winreg.ConnectRegistry(None, hive)
            aKey = winreg.OpenKey(aReg, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | flag)
        except FileNotFoundError as e:
            return [], None, None, None
        except PermissionError as e:
            print("Error: No tienes permisos para acceder a la clave del registro en {}".format(hive))
            return [], None, None, None
        
        count_subkey = winreg.QueryInfoKey(aKey)[0]
        software_list = []
        kaspersky_path = None
        segurmatica_path = None
        segurmatica_version = None
        
        for i in range(count_subkey):
            try:
                asubkey_name = winreg.EnumKey(aKey, i)
                asubkey = winreg.OpenKey(aKey, asubkey_name)
                name = winreg.QueryValueEx(asubkey, "DisplayName")[0]
                try:
                    version = winreg.QueryValueEx(asubkey, "DisplayVersion")[0]
                except EnvironmentError:
                    version = 'undefined'
                
                software_list.append((name, version))
                
                try:
                    install_location = winreg.QueryValueEx(asubkey, "InstallLocation")[0]
                except EnvironmentError:
                    install_location = ''
                    
                if os.path.exists(install_location):
                    if 'Kaspersky' in name:
                        kaspersky_path = install_location
                    if 'Segurmática' in name:
                        segurmatica_path = install_location
                        segurmatica_version = version
            except EnvironmentError:
                continue
                
        return software_list, kaspersky_path, segurmatica_path, segurmatica_version

    software_list1, kaspersky_path1, segurmatica_path1, segurmatica_version1 = _get_installed_apps_windows(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)
    software_list2, kaspersky_path2, segurmatica_path2, segurmatica_version2 = _get_installed_apps_windows(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY)
    software_list3, kaspersky_path3, segurmatica_path3, segurmatica_version3 = _get_installed_apps_windows(winreg.HKEY_CURRENT_USER, 0)
    
    software_list = software_list1 + software_list2 + software_list3
    kaspersky_path = kaspersky_path1 or kaspersky_path2 or kaspersky_path3
    segurmatica_path = segurmatica_path1 or segurmatica_path2 or segurmatica_path3
    segurmatica_version = segurmatica_version1 or segurmatica_version2 or segurmatica_version3
    
    return software_list, kaspersky_path, segurmatica_path, segurmatica_version

def get_installed_apps_linux():
    import subprocess
    software_list = []
    kaspersky_path = None
    segurmatica_path = None

    try:
        result = subprocess.run(['dpkg-query', '-W', '-f=${Package} ${Version}\n'], stdout=subprocess.PIPE)
        installed_packages = result.stdout.decode('utf-8').split('\n')

        for pkg in installed_packages:
            if pkg:
                name, version = pkg.split()
                software_list.append({'name': name, 'version': version})

                if 'kaspersky' in name.lower():
                    kaspersky_path = '/usr/bin/{}'.format(name)
                if 'segurmatica' in name.lower():
                    segurmatica_path = '/usr/bin/{}'.format(name)
    except Exception as e:
        print("Error: {}".format(e))

    return software_list, kaspersky_path, segurmatica_path

def scan_ports(host, start_port, end_port):
    open_ports = []

    def scan_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service_name = socket.getservbyport(port)
                except:
                    service_name = "Unknown"
                open_ports.append("Puerto: {}, Servicio: {}".format(port, service_name))

    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, port)

    return open_ports

def is_remote_desktop_enabled():

    if system == "Windows":
        try:
            # Abre la clave del registro donde se almacena la configuración de Escritorio Remoto
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", 0, winreg.KEY_READ)
            
            # Lee el valor de la clave fDenyTSConnections
            value, regtype = winreg.QueryValueEx(reg_key, "fDenyTSConnections")
            
            # Cierra la clave del registro
            winreg.CloseKey(reg_key)
            
            # Verifica el valor de fDenyTSConnections
            if value == 0:
                return "Habilitado"  # Escritorio Remoto está habilitado
            else:
                return "Deshabilitado"  # Escritorio Remoto está deshabilitado
        except Exception as e:
            print("Error al leer el registro: {}".format(e))
            return "Error al verificar"

    elif system == "Linux":
        try:
            # Verificar si el puerto 3389 está escuchando
            result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
            if "3389" in result.stdout:
                return "Habilitado"  # Escritorio Remoto está habilitado
            else:
                return "Deshabilitado"  # Escritorio Remoto está deshabilitado
        except Exception as e:
            print("Error al verificar el puerto: {}".format(e))
            return "Error al verificar"
    
    else:
        return "Sistema operativo no soportado"

def get_kaspersky_info(kaspersky_path):
    kaspersky_info = {
        "Version de Kaspersky": None,
        "Estado de Actualizacion": None,
        "Iniciado": None,
        "Finalizado": None,
        "Completado": None,
        "Protección de control activada": None,
        "Licencia": None,
        "Control de dispositivos": None,
        "Unido a un KSC": None,
    }

    try:
        # Comprobamos el estado de diferentes componentes de Kaspersky
        stat_output = subprocess.check_output([os.path.join(kaspersky_path, 'avp.com'), 'STATUS'], stderr=subprocess.STDOUT).decode('latin1')
        for line in stat_output.splitlines():
            if 'Protection ' in line:
                kaspersky_info["Protección de control activada"] = line.split()[-1].strip()
            if 'DeviceControl ' in line:
                kaspersky_info["Control de dispositivos"] = line.split()[-1].strip()
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar avp.com (STATUS): {}".format(e))

    try:
        # Comprobamos el estado de diferentes componentes de Kaspersky
        stat_output = subprocess.check_output([os.path.join(kaspersky_path, 'avp.com'), '?'], stderr=subprocess.STDOUT).decode('latin1')
        for line in stat_output.splitlines():
            if 'Kaspersky Application' in line:
                kaspersky_info["Version de Kaspersky"] = line.split()[-1].strip()
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar avp.com ?: {}".format(e))

    try:
        # Crear un archivo por lotes temporal para ejecutar el comando LICENSE /CHECK
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bat') as bat_file:
            bat_file.write('@echo off\n"{}" LICENSE /CHECK\n'.format(os.path.join(kaspersky_path, "avp.com")).encode('latin1'))
            bat_file.write(b'@echo on\n')
            bat_file.close()
            
            # Ejecutar el archivo por lotes temporal
            stat_output_license = subprocess.check_output([bat_file.name], stderr=subprocess.STDOUT).decode('latin1')
            os.remove(bat_file.name)
        
        for line in stat_output_license.splitlines():
            if 'License ID' in line:
                kaspersky_info["Licencia"] = line.split(": ", 1)[1].strip()
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar avp.com (LICENSE /CHECK): {}".format(e))

    try:
        # Obtenemos estadísticas del actualizador
        stat_output_updater = subprocess.check_output([os.path.join(kaspersky_path, 'avp.com'), 'STATISTICS', 'Updater'], stderr=subprocess.STDOUT).decode('latin1')
        for line in stat_output_updater.splitlines():
            if "Time Start:" in line:
                kaspersky_info["Iniciado"] = line.split(": ", 1)[1].strip()
            if "Time Finish:" in line:
                kaspersky_info["Finalizado"] = line.split(": ", 1)[1].strip()
            if "Completion:" in line:
                kaspersky_info["Completado"] = line.split(": ", 1)[1].strip()
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar avp.com (STATISTICS Updater): {}".format(e))
    
    try:
        # Ejecutar el comando 'tasklist' y capturar la salida
        resultado = subprocess.check_output(['tasklist'], shell=True, universal_newlines=True)
        # Verificar si 'klnagent.exe' está presente en la salida
        if 'klnagent.exe' in resultado.lower():
            kaspersky_info["Unido a un KSC"] = "Si"
        else:
            kaspersky_info["Unido a un KSC"] = "No"
    except subprocess.CalledProcessError as e:
        print("Error al ejecutar el comando:", e)

    return kaspersky_info

def get_segurmatica_info(segurmatica_version):
    if system == "Windows":
        return get_segurmatica_info_windows(segurmatica_version)
    if system == "Linux":
        return get_segurmatica_info_linux(segurmatica_version)


#Funcion para obtener la informacion del segurmática de windows
def get_segurmatica_info_windows(segurmatica_version):
    segurmatica_info = {
        "Version": None,
        "Conexión exitosa al servidor": None,
        "Licencia Corporativa": None,
        "Licencia": None,
        "Fecha de expiración": None,
        "Fecha de actualización": None,
        "Protección permanente": None,
        "Resultado de la última búsqueda de código Maligno": None        
    }
    start_time = None
    
    segurmatica_info["Version"] = segurmatica_version
    # Determinar la ruta del archivo según el sistema operativo
    if os.name == 'nt':
        if os.path.exists(r"C:\ProgramData\Segurmatica\Segurmatica Antivirus\Client\System.log"):
            file_path = r"C:\ProgramData\Segurmatica\Segurmatica Antivirus\Client\System.log"
        else:
            file_path = r"C:\Documents and Settings\All Users\Datos de programa\Segurmatica\Segurmatica Antivirus\Client\System.log"
    else:
        print("Sistema operativo no compatible")
        return segurmatica_info

    with open(file_path, 'r', encoding='latin-1') as file:
        lines = file.readlines()

    for line in lines:
        if "Conexión exitosa al servidor" in line:
            segurmatica_info["Conexión exitosa al servidor"] = line.split("Conexión exitosa al servidor ")[-1].strip()
        elif "Autorizado a:" in line and "Fecha de expiración:" in line:
            # Extraer la información de licencia y fecha de expiración
            parts = line.split(". ")
            for part in parts:
                if "Autorizado a:" in part:
                    segurmatica_info["Licencia"] = part.split("Autorizado a: ")[-1].strip()
                elif "Fecha de expiración:" in part:
                    segurmatica_info["Fecha de expiración"] = part.split("Fecha de expiración: ")[-1].strip()
        elif "Antivirus|Licencia corporativa" in line:
            segurmatica_info["Licencia Corporativa"] = line.split("|")[-1].strip()
        elif "Fecha de actualización" in line:
            segurmatica_info["Fecha de actualización"] = line.split(": ")[-1].strip()
        elif "Protección permanente" in line:
            segurmatica_info["Protección permanente"] = line.split(": ")[-1].strip()
        elif "Búsqueda|Inicio" in line:
            # Guardar la hora de inicio de la búsqueda
            start_time = line.split("|")[0].strip()
        elif "Búsqueda|Fin" in line and "Objetos revisados" in line:
            # Actualizar con la última ocurrencia encontrada
            objetos_revisados = line.split(": ")[-1].strip()
            segurmatica_info["Resultado de la última búsqueda de código Maligno"] = "{} Objetos revisados: {}".format(start_time, objetos_revisados)

    return segurmatica_info

#Funcion para obtener la informacion del segurmática de linux
def get_segurmatica_info_linux(segurmatica_version):
    segurmatica_info = {
        "Version": None,
        "Licencia": None,
        "Fecha de expiración": None,
        "Protección permanente": None,
        "Resultado de la última búsqueda de código Maligno": None,
        "Objetos revisados": None,
        "Fecha de la actualización": None
    }

    segurmatica_info["Version"] = segurmatica_version
    # Ejecutar el comando y capturar la salida
    command = "segavcli info --show"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error ejecutando el comando")
        return segurmatica_info

    output = result.stdout.splitlines()

    for line in output:
        if "Autorizado a" in line:
            segurmatica_info["Licencia"] = line.split(": ")[-1].strip()
        elif "Fecha de expiración" in line:
            segurmatica_info["Fecha de expiración"] = line.split(": ")[-1].strip()
        elif "Deshabilitada" in line or "Habilitada" in line:
            segurmatica_info["Protección permanente"] = line.split(": ")[-1].strip()
        elif "Fecha" in line and "Revisados" not in line:
            segurmatica_info["Resultado de la última búsqueda de código Maligno"] = line.split(": ")[-1].strip()
        elif "Revisados" in line:
            segurmatica_info["Objetos revisados"] = line.split(": ")[-1].strip()
        elif "Fecha de la actualización" in line:
            segurmatica_info["Fecha de la actualización"] = line.split(": ")[-1].strip()

    return segurmatica_info

def get_installed_security_patches():
    patches_list = []

    if system == "Windows":
        try:
            # Conectar al servicio WMI
            c = wmi.WMI()

            # Consultar la información de los parches de seguridad instalados
            patches = c.Win32_QuickFixEngineering()

            for patch in patches:
                patches_list.append("ID: {0}, Descripción: {1}, Instalado en: {2}".format(
                    patch.HotFixID, patch.Description, patch.InstalledOn))

            if patches_list:
                return patches_list
            else:
                return ["No se encontraron parches de seguridad instalados en Windows."]
        except Exception as e:
            return ["Error al obtener la lista de parches de seguridad en Windows: {}".format(e)]

    elif system == "Linux":
        try:
            # Verificar si el sistema es basado en Debian/Ubuntu
            result = subprocess.run(["which", "dpkg"], capture_output=True, text=True)
            if result.returncode == 0:
                # Sistema basado en Debian/Ubuntu
                command = "dpkg-query -l | grep -i security"
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                patches = result.stdout.splitlines()
                if patches:
                    return patches
                else:
                    return ["No se encontraron parches de seguridad instalados en Linux (Debian/Ubuntu)."]

            # Verificar si el sistema es basado en Red Hat/Fedora
            result = subprocess.run(["which", "rpm"], capture_output=True, text=True)
            if result.returncode == 0:
                # Sistema basado en Red Hat/Fedora
                command = "rpm -qa | grep -i security"
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                patches = result.stdout.splitlines()
                if patches:
                    return patches
                else:
                    return ["No se encontraron parches de seguridad instalados en Linux (Red Hat/Fedora)."]

            return ["No se pudo determinar el sistema de paquetes en Linux."]
        except Exception as e:
            return ["Error al obtener la lista de parches de seguridad en Linux: {}".format(e)]

    else:
        return ["Sistema operativo no soportado."]

def listar_carpetas_compartidas():
    carpetas = []
    if system == 'Windows':
        carpetas_compartidas = os.popen('net share').read()
        lineas = carpetas_compartidas.split('\n')
        for linea in lineas:
            linea = linea.strip()  # Quita espacios en blanco al inicio y al final
            if linea and not linea.startswith("-----") and not linea.startswith(" "):
                carpetas.append(linea)  # Mantiene la línea completa
    elif system == 'Linux':
        carpetas_compartidas = os.popen('smbclient -L localhost').read()
        lineas = carpetas_compartidas.split('\n')
        for linea in lineas:
            linea = linea.strip()  # Quita espacios en blanco al inicio y al final
            if linea and "Disk" in linea:
                carpetas.append(linea)  # Mantiene la línea completa

    # Elimina la primera y la última línea
    if len(carpetas) > 1:
        carpetas = carpetas[1:-1]

    return carpetas

#Detectar dispositivos conectados a la pc ya sean usb o de otro tipo
def obtener_dispositivos_usb():
    wmi_client = wmi.WMI()

    dispositivos = {
        "Cámaras": [],
        "Impresoras Activas": [],
        "Escáneres": [],
        "Dispositivos USB": [],
        "Teclados": [],
        "Ratones": [],
        "Discos": []
    }

    # Detectar cámaras
    for camara in wmi_client.InstancesOf("Win32_PnPEntity"):
        if camara.Description and "camera" in camara.Description.lower():
            dispositivos["Cámaras"].append(camara.Description)

    # Detectar impresoras activas
    for impresora in wmi_client.InstancesOf("Win32_Printer"):
        if not impresora.WorkOffline:
            dispositivos["Impresoras Activas"].append(impresora.Name)

    # Detectar escáneres
    for escaner in wmi_client.InstancesOf("Win32_PnPEntity"):
        if escaner.Description and "scanner" in escaner.Description.lower():
            dispositivos["Escáneres"].append(escaner.Description)

    # Detectar dispositivos USB con información específica
    for usb in wmi_client.InstancesOf("Win32_DiskDrive"):
        dispositivos["Dispositivos USB"].append({
            "Caption": getattr(usb, 'Caption', ''),
            "Description": getattr(usb, 'Description', ''),
            "Model": getattr(usb, 'Model', ''),
            "Name": getattr(usb, 'Name', ''),
            "SerialNumber": getattr(usb, 'SerialNumber', ''),
            "PNPDeviceID": getattr(usb, 'PNPDeviceID', ''),
            "InterfaceType": getattr(usb, 'InterfaceType', '')
        })

    # Detectar teclados
    for teclado in wmi_client.InstancesOf("Win32_Keyboard"):
        dispositivos["Teclados"].append(teclado.Description)

    # Detectar ratones
    for raton in wmi_client.InstancesOf("Win32_PointingDevice"):
        dispositivos["Ratones"].append(raton.Description)

    # Detectar discos
    for drive in wmi_client.InstancesOf("Win32_DiskDrive"):
        dispositivos["Discos"].append(drive.Caption)

    for disk in wmi_client.InstancesOf("Win32_LogicalDisk"):
        dispositivos["Discos"].append(disk.Caption)

    return dispositivos

#Devolver el resultado formateado de los dispositivos conectados a la pc
def dispositivos_usb_formateados():
    dispositivos = obtener_dispositivos_usb()
    dispositivos_formateados = {}

    for tipo, lista in dispositivos.items():
        if tipo == "Dispositivos USB":
            dispositivos_formateados[tipo] = []
            for dispositivo in lista:
                dispositivo_str = "Caption: {}, Description: {}, Model: {}, Name: {}, SerialNumber: {}, PNPDeviceID: {}, InterfaceType: {}".format(
                    dispositivo.get('Caption', ''), dispositivo.get('Description', ''), 
                    dispositivo.get('Model', ''), dispositivo.get('Name', ''), 
                    dispositivo.get('SerialNumber', ''), dispositivo.get('PNPDeviceID', ''), 
                    dispositivo.get('InterfaceType', '')
                )
                dispositivos_formateados[tipo].append(dispositivo_str)
        else:
            dispositivos_formateados[tipo] = lista

    return dispositivos_formateados

#Verificar si los puertos usb estan cerrados o abiertos
def list_usb_ports():
    try:
        if os.name == 'nt':  # Windows
            process = subprocess.Popen(['wmic', 'path', 'Win32_PnPEntity', 'where', 'Caption like "%USB%"', 'get', 'Caption,Status,DeviceID'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            stdout = stdout.decode('utf-8', errors='ignore')  # Decodificar la salida y omitir errores
            stderr = stderr.decode('utf-8', errors='ignore')
            if process.returncode == 0:
                return stdout
            else:
                return "Error listing USB ports: {}".format(stderr)
        else:
            return "Este script solo es compatible con Windows."
    except Exception as e:
        return "Error listing USB ports: {}".format(e)

#Verificar otros puertos
def check_port_state(port_name, port_type):
    try:
        if os.name == 'nt':  # Windows
            if port_type == 'PnPEntity':
                process = subprocess.Popen(['wmic', 'path', 'Win32_PnPEntity', 'where', 'Caption like "%{}%"'.format(port_name), 'get', 'Status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif port_type == 'NetworkAdapter':
                process = subprocess.Popen(['wmic', 'path', 'Win32_NetworkAdapter', 'where', 'NetConnectionStatus=2', 'get', 'Name,NetConnectionStatus'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            stdout = stdout.decode('utf-8', errors='ignore')  # Decodificar la salida y omitir errores
            stderr = stderr.decode('utf-8', errors='ignore')
            if process.returncode == 0:
                return "OK" in stdout
            else:
                return "Error checking port state: {}".format(stderr)
        else:
            return "Este script solo es compatible con Windows."
    except Exception as e:
        return "Error checking port state: {}".format(e)

#Devolver el estado en el que estan esos otros puertos
def devolver_estado_puertos():
    # Verifica si un puerto específico está abierto
    ports_to_check = {
        "Serial": "PnPEntity",
        "LPT": "PnPEntity",
        "Ethernet": "NetworkAdapter",
        "HDMI": "PnPEntity",
        "VGA": "PnPEntity",
        "DVI": "PnPEntity",
        "Audio": "PnPEntity",
        "SD": "PnPEntity"
    }

    port_states = []
    for port_name, port_type in ports_to_check.items():
        if check_port_state(port_name, port_type):
            port_states.append("El puerto {} está abierto".format(port_name))
        else:
            port_states.append("El puerto {} está cerrado".format(port_name))
    return port_states

#Verificar si está unido a un kms
def union_a_kms():
    if system == 'Windows':
        try:
            # Ejecutar el comando 'tasklist' y capturar la salida
            resultado = subprocess.check_output(['tasklist'], shell=True, universal_newlines=True)
            # Verificar si 'kms-service.exe' está presente en la salida
            if 'kms-service.exe' in resultado.lower():
                return "Si"
            else:
                return "No"
        except subprocess.CalledProcessError as e:
            print("Error al ejecutar el comando:", e)
    elif system == 'Linux':
        return 'No disponible para linux'
    else:
        print('Sistema operativo no soportado')

def historial_dispositivos():
    if system == 'Windows' and '10' in platform.version():
        file_path = r'C:\Windows\INF\setupapi.dev.log'
        if not os.path.exists(file_path):
            print("El archivo {} no existe.".format(file_path))
            return []

        devices_info = []  # Lista para almacenar la información de cada dispositivo
        seen_identifiers = set()  # Conjunto para almacenar identificadores únicos ya vistos

        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()

                for i, line in enumerate(lines):
                    if "Device Install (Hardware initiated)" in line:
                        device_info = {
                            "Tipo de dispositivo": "Desconocido",
                            "Identificador único": "",
                            "Fecha de inicio": ""
                        }

                        line_parts = line.split(' ')
                        if len(line_parts) > 7:
                            line1 = line_parts[7].strip()
                            if "SWD\\WPDBUSENUM" in line1:
                                device_info["Tipo de dispositivo"] = "Dispositivo de almacenamiento"
                            elif "USB\\VID" in line1:
                                device_info["Tipo de dispositivo"] = "Dispositivo Móvil"
                            elif "HID\\VID" in line1:
                                device_info["Tipo de dispositivo"] = "Dispositivo de Interfaz humana"

                            if line1.startswith('SWD\\WPDBUSENUM\\_??_'):
                                id_line_larga = line1.split('#')
                                if len(id_line_larga) > 2:
                                    device_info["Identificador único"] = id_line_larga[2]
                            elif line1.startswith('SWD\\WPDBUSENUM\\{'):
                                id_line_corta = line1.split('#')
                                if len(id_line_corta) > 1:
                                    device_info['Identificador único'] = id_line_corta[1]
                            elif line1.startswith('USB'):
                                idusb = line1.split('USB')
                                device_info['Identificador único'] = idusb[1]
                            elif line1.startswith('HID'):
                                idhid = line1.split('\\')
                                device_info['Identificador único'] = idhid[2]

                            # Capturar la primera línea después de "Device Install (Hardware initiated)"
                            if i + 1 < len(lines):
                                device_info["Fecha de inicio"] = lines[i + 1].strip()

                            # Añadir el dispositivo a la lista solo si el identificador es único
                            if device_info["Identificador único"] not in seen_identifiers:
                                devices_info.append(device_info)
                                seen_identifiers.add(device_info["Identificador único"])

            return devices_info

        except Exception as e:
            print("Error al leer el archivo: {}".format(e))
            return []

def write_to_txt_and_db(fecha, nombre_pc, ip_fisica, user_active, users_admin, all_users, system_data, port_data, device_data, usb_ports, port_states, kaspersky_data, segurmatica_data, escritorio_remoto, parches, carpetas_compartidas, kms, device_histoty):
    # Guardar en TXT (código original)
    directorio = os.path.dirname(os.path.abspath(__file__))
    fichero = os.path.join(directorio, "system_info.txt")
    with open(fichero, "w") as file:
        file.write("\n-----------------------------------------\n")
        file.write("\nFecha de Modificacion: {}\n".format(fecha))
        file.write("\nNombre de la pc: {}\n".format(nombre_pc))
        file.write("\nDIreccion IP: {}\n".format(ip_fisica))
        file.write("\nUsuario activo: {}\n".format(user_active))
        file.write("\nUsuarios Administrador:\n")
        for user in users_admin:
            file.write("{}\n".format(user))
        file.write("\nUsuarios del Sistema\n")
        for user_local in all_users:
            file.write("{}\n".format(user_local))
        file.write("\nAplicaciones Instaladas:\n")
        for app in system_data:
            file.write("{}, {}\n".format(app[0], app[1]))
        file.write("\nEscaneo de Puertos:\n")
        for item in port_data:
            if isinstance(item, tuple) and len(item) == 2:
                port, service = item
                file.write("Port: {}, Service: {}\n".format(port, service))
            else:
                file.write("{}\n".format(item))

        file.write("\nDispositivos Conectados:\n")
        
        file.write("\nImpresoras Activas:\n")
        for impresora in device_data["Impresoras Activas"]:
            file.write("{}\n".format(impresora))

        file.write("\nDispositivos USB:\n")
        for dispositivo in device_data["Dispositivos USB"]:
            file.write("{}\n".format(dispositivo))

        file.write("\nTeclados:\n")
        for teclado in device_data["Teclados"]:
            file.write("{}\n".format(teclado))

        file.write("\nMouse:\n")
        for raton in device_data["Ratones"]:
            file.write("{}\n".format(raton))

        file.write("\nDiscos:\n")
        for disco in device_data["Discos"]:
            file.write("{}\n".format(disco))
        
        file.write("\nEstado de los puertos USB:\n")
        linea = usb_ports.strip().split('\n')
        for usb in linea:
            if usb.strip():
                usb = usb.strip()
                file.write("{}\n".format(usb))

        file.write("\nEstado de otros puertos:\n")
        for puerto in port_states:
            file.write("{}\n".format(puerto))

        if kaspersky_data == "No está instalado":
            file.write("\n")
        else:
            file.write("\nInformación de Kaspersky:\n")
            for key, value in kaspersky_data.items():
                if value:
                    file.write("{}: {}\n".format(key, value))
        if segurmatica_data == "No está instalado":
            file.write("\n")
        else:
            file.write("\nInformación de Segurmática:\n")
            for key, value in segurmatica_data.items():
                if value:
                    file.write("{}: {}\n".format(key, value))

        file.write("\nEscritorio Remoto:\n")
        file.write("{}\n".format(escritorio_remoto))

        file.write("\nParches de Seguridad:\n")
        for parche in parches:
            file.write("{}\n".format(parche))

        file.write("\nEstado de las carpetas compartidas:\n")
        for carpeta in carpetas_compartidas:
            file.write("{}\n".format(carpeta))
        
        file.write("\nUnido al servivio KMS:\n")
        file.write("{}\n".format(kms))
        
        file.write('\nHistorial de dispositivos conectados\n')
        for device in device_histoty:
            for clave, valor in device.items():
                file.write("{}: {}\n".format(clave,valor))
            file.write('\n')

# Preparar datos para PostgreSQL
    data = {
        "fecha": fecha,
        "nombre_pc": nombre_pc,
        "ip_fisica": ip_fisica,
        "user_active": user_active,
        "users_admin": users_admin,
        "all_users": all_users,
        "system_data": system_data,
        "port_data": port_data,
        "device_data": device_data,
        "usb_ports": usb_ports,
        "port_states": port_states,
        "kaspersky_data": kaspersky_data,
        "segurmatica_data": segurmatica_data,
        "escritorio_remoto": escritorio_remoto,
        "parches": parches,
        "carpetas_compartidas": carpetas_compartidas,
        "kms": kms,
        "device_histoty": device_histoty
    }

    # Enviar a PostgreSQL
    create_database_structure()  # Asegurarse de que la estructura existe
    send_to_postgresql(data)

def create_and_schedule_bat_file():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    bat_file_path = os.path.join(base_dir, 'backup_script.bat')
    vbs_file_path = os.path.join(base_dir, 'run_backup_script.vbs')
    python_script_path = os.path.join(base_dir, os.path.basename(__file__))
    
    # Comprobar si el ejecutable existe
    exe_script_path = python_script_path.replace('.py', '.exe')
    
    if os.path.isfile(exe_script_path):
        script_to_run = exe_script_path
    else:
        script_to_run = python_script_path

    with open(bat_file_path, 'w') as bat_file:
        bat_file.write('@echo off\n')
        bat_file.write('"{}"\n'.format(script_to_run))

    with open(vbs_file_path, 'w') as vbs_file:
        vbs_file.write('Set WshShell = CreateObject("WScript.Shell")\n')
        vbs_file.write('WshShell.Run chr(34) & "{}" & chr(34), 0, False\n'.format(bat_file_path))

    # Programar el archivo .bat en el Programador de Tareas de Windows
    task_name = "BackupScriptTask"
    # Comprobar si la tarea ya existe
    query_command = 'schtasks /query | findstr "{}"'.format(task_name)
    result = subprocess.call(query_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result != 0:  # Si la tarea no existe
        schedule_command = 'schtasks /create /tn "{}" /tr "cmd /c start /min cmd.exe /c \\"{}\\"" /sc minute /mo 1 /ru {}'.format(task_name, vbs_file_path, os.getenv("USERNAME"))
        subprocess.call(schedule_command, shell=True)
        print("Archivo .bat programado en el Programador de Tareas de Windows para ejecutarse cada hora.")
    else:
        print("La tarea ya existe en el Programador de Tareas de Windows.")

ip_fisica = get_ip()
print("Procesando.......")
if ip_fisica:
    port_data = scan_ports(ip_fisica, 1, 1024)
else:
    port_data = "No se pudo obtener la IP de la interfaz física."
    print(port_data)

#create_and_schedule_bat_file()
system_data, kaspersky_path, segurmatica_path, segurmatica_version = get_installed_apps()

if kaspersky_path:
    kaspersky_data = get_kaspersky_info(kaspersky_path)
else:
    kaspersky_data = "No está instalado"

if segurmatica_path:
    segurmatica_data = get_segurmatica_info(segurmatica_version)
else:
    segurmatica_data = "No está instalado"
nombre_pc = obtener_nombre_pc()
device_data = dispositivos_usb_formateados()
usb_ports = list_usb_ports()

escritorio_remoto = is_remote_desktop_enabled()
parches = get_installed_security_patches()
carpetas_compartidas = listar_carpetas_compartidas()
fecha = get_execution_date()
user_active = get_active_user()
users_admin = get_admin_users()
all_users = get_all_users()
port_states = devolver_estado_puertos()
kms = union_a_kms()
device_histoty = historial_dispositivos()
write_to_txt_and_db(fecha, nombre_pc, ip_fisica, user_active, users_admin, all_users, system_data, port_data, device_data, usb_ports, port_states, kaspersky_data, segurmatica_data, escritorio_remoto, parches, carpetas_compartidas, kms, device_histoty)
print("Datos del sistema escritos en 'system_info.txt'.")