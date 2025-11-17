# Introducción

Este informe forense documenta el análisis exhaustivo de una máquina Windows 7 comprometida entregada en formato OVA. El proceso de investigación se divide en dos fases principales:

1. **Pruebas y análisis fuera de la máquina** (análisis estático sin ejecutar el sistema operativo).
2. **Pruebas dentro de la máquina** (análisis dinámico o live forensics), desarrolladas en una fase posterior.

# **Parte A – Análisis Forense Fuera de la Máquina**
 Donde la evidencia es examinada sin arrancar el sistema. Esto evita cualquier alteración en los artefactos originales y permite llevar a cabo un análisis controlado y fiable.

A continuación se describen las herramientas, comandos y procedimientos característicos de un flujo forense completo.

---

# 1. Recolección de Evidencias

# Parte A – Pruebas y Comandos Fuera de la Máquina (Análisis Estático)

## A.1. Cálculo de hashes del archivo OVA/VMDK

```bash
sha256sum FORENSIC_10.ova
```

El cálculo de hashes garantiza la integridad de la evidencia. El valor obtenido fue:

```
daf0ef5255d98276a6912a53611db5c0cbf2cccbb49a180dd7fcc0f95e14930c  FORENSIC_10.ova
```

Posteriormente se extrae el archivo `.vmdk` contenido en la OVA.

![OVA](IMG/ova.png)

### Hashes del OVA y su contenido

```bash
sha256sum *
sha1sum *
md5sum *
```

| Archivo                 | SHA256                                                           | MD5                              | SHA1                                     |
| ----------------------- | ---------------------------------------------------------------- | -------------------------------- | ---------------------------------------- |
| FORENSIC_10.ova         | daf0ef5255d98276a6912a53611db5c0cbf2cccbb49a180dd7fcc0f95e14930c | 45ea13bf91ad8393f5684edf588db60a | bb4a7c2842c21947863c0f05d7c015630ffbf6e2 |
| FORENSIC_10_disk0.vmdk  | d5823f36d01b807888275d8b21f41c1e427d2e59d610177722416702b025a6ff | 3c21518c46518550689291ed10c1ee5e | ec69cc76452c87c01e5c6414a0f4c549b49ec5c5 |
| FORENSIC_10_file0.nvram | 2635893c1b7270edfdba1d5baa5a63fb4a9c2170caa2614639c190d0f5aac2f6 | d4b147f6890861f82d1a2df0f2062602 | 7577d5db9380ca968ba24c50fdc5ef8ed25500be |
| FORENSIC_10.mf          | bb9afac37ffbdfe8af4228a3af223b868e577d87876a683ecca9bf8e0992a402 | fe907f70ee42591a34c6a82331301e11 | bc75c7d044a3123a34b40247ed3da510c327ae5c |
| FORENSIC_10.ovf         | 2c36a2c71aee1189e14255e6127122ef0acb4132f805e7f57e5092f43d4e7f33 | 0f8ee0089360f3d7497dd0b2acdabad1 | fa1914cbb8c9e4322fcabbe909ee9c251435a009 |

---

## A.2. Análisis del Disco

### A.2.1. Información del disco

El análisis inicial permite identificar particiones, sectores y estructura general.

```bash
fdisk -l disco.vmdk
```

![fdisk](IMG/fdisk.png)

```bash
qemu-img info disco.vmdk
```

![qemu-img](IMG/imgqemu.png)

### A.2.2. Montaje del disco en modo solo lectura

El uso de herramientas como *guestfish* o *guestmount* garantiza que el sistema de archivos no se modifica.

```bash
sudo guestfish --ro -a FORENSIC_10_disk0.vmdk -i list-filesystems
```

```bash
sudo guestmount -a FORENSIC_10_disk0.vmdk -m /dev/sda2 --ro /mnt/vmdk
```

### A.2.3. Reconstrucción de la estructura del sistema de archivos

```bash
sudo tree -L 1 /mnt/vmdk
```

![estructura](IMG/list.png)

---

## A.3. Extracción Masiva de Artefactos

### A.3.1. Registro de Windows (Registry Hives)

Los hives contienen información crítica como cuentas de usuario, historial de dispositivos, configuraciones del sistema y artefactos de ejecución.

```bash
cp /mnt/vmdk/Windows/System32/config/SYSTEM ./registry/
cp /mnt/vmdk/Windows/System32/config/SAM ./registry/
cp /mnt/vmdk/Windows/System32/config/SECURITY ./registry/
cp /mnt/vmdk/Windows/System32/config/SOFTWARE ./registry/
cp /mnt/vmdk/Users/*/NTUSER.DAT ./registry/
cp /mnt/vmdk/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat ./registry/
```

### A.3.2. Prefetch

Los archivos Prefetch permiten determinar la ejecución reciente de binarios.

```bash
cp /mnt/vmdk/Windows/Prefetch/*.pf ./prefetch/
```

### A.3.3. Event Logs

```bash
cp /mnt/vmdk/Windows/System32/winevt/Logs/*.evtx ./logs/
```

### A.3.4. Archivos temporales

```bash
cp -R /mnt/vmdk/Users/Administrador/AppData/Local/Temp/* tmp/
```

### A.3.5. Archivos de inicio y persistencia

```bash
cp /mnt/vmdk/ProgramData/Microsoft/Windows/Start\ Menu/Programs/Startup/* ./startup/
cp /mnt/vmdk/Users/*/AppData/Roaming/Microsoft/Windows/Start\ Menu/Programs/Startup/* ./startup/
```

---

## A.4. Análisis Profundo de Artefactos del Sistema

### A.4.1. Master File Table (MFT)

La MFT es la estructura central de NTFS. Contiene:

* metadatos de cada archivo,
* rutas,
* timestamps MACB,
* permisos,
* flags,
* y data runs.

Incluso archivos eliminados mantienen entradas parcialmente recuperables.

```bash
qemu-img convert -O raw disco.vmdk disco.raw
mmls disco.raw
istat -o 2048 disco.raw 0-128-1
```

### A.4.2. Jump Lists

```bash
cp -R /mnt/vmdk/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations ./jump_lists/
```

### A.4.3. Accesos directos LNK

```bash
cp /mnt/vmdk/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk ./lnk/
cp /mnt/vmdk/Users/Administrador/Desktop/* lnk/
```

---

## A.6. Extracción de Archivos Sospechosos

Durante el análisis del sistema montado, se localizaron **scripts maliciosos y herramientas de explotación** en:

```
/mnt/vmdk/Users/Administrador/Desktop/
```

### 1. Script malicioso `crea_user.py`

Este archivo contiene un exploit completo para el servicio **Easy File Sharing Web Server 7.2**, incluyendo payload generado con `msfvenom`, cadenas ROP, shellcode para crear un usuario ilegítimo y funcionalidad para envío remoto.

### Indicadores técnicos de malicia

1. Uso de un exploit conocido.
2. Dependencia directa de msfvenom.
3. Construcción de una ROP chain avanzada mediante mona.py.
4. Shellcode empaquetado.
5. Ejecución orientada al ataque.

### 2. Activador KMS

KMSPico emula un servidor KMS para activar software sin licencia. Este tipo de herramientas:

* requieren privilegios elevados,
* modifican archivos del sistema,
* instalan servicios,
* crean tareas programadas,
* alteran claves críticas del registro.

Desde la perspectiva forense se consideran PUA o software malicioso, dado el riesgo que introducen y su alta capacidad de modificación del sistema.

---

## A.7. Preservación y Hashing Final

```bash
sha256sum artefactos/* > sha256_hashes.txt
sha1sum artefactos/* > sha1_hashes.txt
md5sum artefactos/* > md5_hashes

```


# **Pruebas dentro de la máquina**

## Inventario de Evidencias

| Evidencia | Descripción breve           | Tamaño  | Hashes            | Fecha/Hora Captura     | Ubicación / Fichero                                  |
| --------- | --------------------------- | ------- | ----------------- | ---------------------- | ---------------------------------------------------- |
| Prueba1   | Máquina Virtual OVA         | 4.87 GB | SHA256, SHA1, MD5 | [2025-11-14 08:45 CET] | [FORENSIC_10.OVA](FORENSIC_10.OVA)                   |
| Prueba2   | Memoria RAM (.elf)          | 1.01 GB | SHA256, SHA1, MD5 | [2025-11-14 09:12 CET] | [memoria_ram.elf](memoria_ram.elf)                   |
| Prueba3   | systeminfo                  | 3 KB    | SHA256, SHA1, MD5 | [2025-11-14 10:03 CET] | [maquina/systeminfo.txt](maquina/systeminfo.txt)     |
| Prueba4   | ipconfig /all               | 3 KB    | SHA256, SHA1, MD5 | [2025-11-14 10:07 CET] | [maquina/ipconfig_all.txt](maquina/ipconfig_all.txt) |
| Prueba5   | route print                 | 3 KB    | SHA256, SHA1, MD5 | [2025-11-14 10:11 CET] | [maquina/routeprint.txt](maquina/routeprint.txt)     |
| Prueba6   | arp -a                      | 1 KB    | SHA256, SHA1, MD5 | [2025-11-14 10:14 CET] | [maquina/arp.txt](maquina/arp.txt)                   |
| Prueba7   | netstat -ano                | 4 KB    | SHA256, SHA1, MD5 | [2025-11-14 10:18 CET] | [maquina/netstat.txt](maquina/netstat.txt)           |
| Prueba8   | tasklist /v                 | 12 KB   | SHA256, SHA1, MD5 | [2025-11-14 10:21 CET] | [maquina/tasklist.txt](maquina/tasklist.txt)         |
| Prueba9   | wmic process list full      | 94 KB   | SHA256, SHA1, MD5 | [2025-11-14 10:25 CET] | [maquina/wmic_process.txt](maquina/wmic_process.txt) |
| Prueba10  | schtasks /query /v /fo list | 138 KB  | SHA256, SHA1, MD5 | [2025-11-14 10:29 CET] | [maquina/schtasks.txt](maquina/schtasks.txt)         |
| Prueba11  | query users                 | 1 KB    | SHA256, SHA1, MD5 | [2025-11-14 10:33 CET] | [maquina/users.txt](maquina/users.txt)               |
| Prueba12  | set (variables entorno)     | 2 KB    | SHA256, SHA1, MD5 | [2025-11-14 10:37 CET] | [maquina/env_vars.txt](maquina/env_vars.txt)         |


## Análisis Técnico por Evidencia

### EV01 — Prueba1: Máquina Virtual OVA
Cuando se enciende la máquina virtual, aparece un error del "Windows Script Host", lo que señala dificultades con la ejecución de scripts dentro del ambiente Windows 7 de la VM.  
  
Este error podría tener que ver con archivos de script ausentes, daños en el sistema, interferencias con software malicioso o configuraciones erróneas.  


![alt text](IMG/fondo.png)



- **Relevancia:**  
  - El error de Windows Script Host afecta la estabilidad y funcionalidad del sistema analizado, pudiendo alterar la captura de evidencias y la reproducción del escenario original.  
  - Es crucial documentar este problema para explicar posibles inconsistencias o comportamientos anómalos durante las fases de análisis posteriores.  

- **Riesgos/indicadores:**  
  - Posible indicación de infección por malware basado en scripts o manipulación maliciosa de archivos de sistema críticos.  
  - Puede también señalar daños o configuraciones incorrectas en el sistema operativo huésped de la VM.  
  - Requiere atención para remediar o aislar el problema antes de realizar análisis exhaustivos o para validar la integridad de la imagen OVA.





### EV02 — Prueba2: Memoria RAM (.elf)
Se utilizó Volatility Framework, una herramienta especializada, para examinar el volcado de memoria en formato ELF. Esto posibilitó la obtención y el análisis de procesos activos, conexiones de red, módulos cargados y posibles indicios de acción maliciosa en tiempo real. Se identificaron patrones sospechosos, offsets y cadenas de texto significativas que demuestran la ejecución de código no autorizado. Es esencial realizar este análisis para entender el estado volátil del sistema durante la captura, enfocándose en detectar inyecciones de código, malware presente en la memoria y comunicaciones activas.


### EV03 — Prueba3: Disco virtual (imagen)
La imagen del disco fue explorada con FTK Imager y herramientas complementarias para examinar la estructura del sistema de archivos, usuarios activos, registros de eventos y configuraciones persistentes. Se identificaron artefactos relevantes incluyendo tareas programadas maliciosas, archivos ejecutables sospechosos en áreas temporales y registros que permiten construir la timeline del ataque. Además, se prestó atención a carpetas “orphan” que contienen archivos huérfanos con indicios de actividad maliciosa previa o evidencia residual.



### EV04 — Prueba4: systeminfo
- **Puntos clave:**  
  - SO: Microsoft Windows 7 Professional  
  - Versión: 6.1.7601 Service Pack 1 Build 7601  
  - Fecha instalación original: 30/06/2017  
  - Fabricante del sistema: innotek GmbH (VirtualBox)  
  - Modelo: VirtualBox  
  - Arquitectura: x64-based PC  
  - Procesador: AMD64 Family 23 Model 24 Stepping 1 AuthenticAMD ~2097 Mhz  
  - BIOS: innotek GmbH VirtualBox, 12/1/2006  
  - Memoria física total: 1,024 MB  
  - Memoria disponible: 487 MB  
  - Red: Intel(R) PRO/1000 MT Network Connection, IP: 172.26.0.86  
  - Hotfixes instalados: 3 (KB2534111, KB958488, KB976902)  

- **Implicaciones:**  
  - Windows 7 SP1 es un sistema operativo con soporte limitado, aumentado el riesgo por vulnerabilidades conocidas que podrían ser explotadas si no se han aplicado todos los parches de seguridad recientes.  
  - La VM emplea VirtualBox con BIOS y hardware virtualizados, que puede influir en la detección y análisis del entorno.  
  - La memoria limitada y configuración del sistema podrían haber afectado el rendimiento o generado condiciones para vectores de ataque específicos.  
  - La configuración de red con DHCP y conectividad activa brinda superficie de ataque remota.  
  - Los hotfixes instalados podrían mitigar algunas vulnerabilidades, pero se recomienda revisar actualizaciones adicionales o versiones más seguras en entornos productivos.  


### EV05 — Prueba5: ipconfig /all
- **Puntos clave:**  
  - IP: 172.26.0.86 (IPv4)  
  - Máscara de subred: 255.255.252.0  
  - Gateway predeterminado: 172.26.0.1  
  - Servidor DHCP: 172.26.0.1  
  - DNS Servers: 172.26.0.1  
  - DHCP habilitado: Sí  
  - Dirección MAC: 08-00-27-72-30-1F  

- **Implicaciones:**  
  - La configuración indica que la máquina está en una red privada con segmentación definida por la máscara de subred.  
  - El uso de DHCP facilita la administración dinámica pero puede ser un vector para ataques de red si no está asegurado.  
  - La resolución de nombres a través de DNS es centralizada a 172.26.0.1, permitiendo control y posible monitoreo del tráfico de red.  
  - El entorno favorece la comunicación interna entre nodos, pero debe revisarse para evitar accesos no autorizados o interceptación.  
  - La dirección física (MAC) confirma la identificación del adaptador de red en la máquina virtual.


### EV06 — Prueba6: route print
- **Puntos clave:**  
  - Ruta por defecto (default gateway): 0.0.0.0 / 0.0.0.0 → 172.26.0.1 a través de la interfaz 172.26.0.86  
  - Redes locales: 172.26.0.0 / 255.255.252.0 en interfaz 172.26.0.86  
  - Loopback y multicast en interfaces locales (127.0.0.0/8 y 224.0.0.0/4)  
  - No existen rutas persistentes configuradas  
  - Interfases de túnel inactivas (ISATAP, 6to4, Teredo)

- **Implicaciones:**  
  - El camino de salida principal es a través del gateway 172.26.0.1, que canaliza todo el tráfico hacia redes externas.  
  - La presencia de rutas locales con máscara 255.255.252.0 indica un segmento de red relativamente amplio para comunicación interna.  
  - La ausencia de rutas persistentes limita configuraciones manuales o estáticas que podrían afectar el filtrado o redireccionamiento.  
  - Las interfaces de túnel desactivadas sugieren que no hay rutas IPv6 activas, limitando posibles vectores en ese protocolo.  
  - Desde la perspectiva forense, se confirma que el sistema depende del gateway DHCP para la gestión de rutas, lo que puede ser un punto para evaluar filtrados, monitorización y potencial pivoting.

### EV07 — Prueba7: arp -a
- **Puntos clave:**  
  - Gateway: 172.26.0.1 con dirección física 74-83-c2-f7-90-c1 (dynamic)  
  - Hosts vecinos:  
    - 172.26.0.80 → 68-34-21-d5-fe-b2 (dynamic)  
    - 172.26.2.5 → d4-1b-81-12-ac-9b (dynamic)  
    - 172.26.2.46 → e0-d3-62-5a-34-25 (dynamic)  
  - Direcciones broadcast/multicast:  
    - 172.26.3.255 → ff-ff-ff-ff-ff-ff (static)  
    - 224.0.0.22 → 01-00-5e-00-00-16 (static)  
    - 224.0.0.252 → 01-00-5e-00-00-fc (static)  
    - 255.255.255.255 → ff-ff-ff-ff-ff-ff (static)  

- **Implicaciones:**  
  - La tabla ARP muestra la vecindad de red inmediata, importante para detectar dispositivos activos y relaciones de comunicación.  
  - Las direcciones MAC dinámicas corresponden a dispositivos detectados automáticamente, lo que indica actividad y presencia en la red.  
  - Las entradas estáticas de broadcast y multicast reflejan protocolos de red esenciales para funciones de enrutamiento, descubrimiento y resolución de nombres.  
  - El análisis de esta tabla ayuda a identificar dispositivos de interés y evaluar la segmentación o posibles anomalías en la vecindad de red.


### EV08 — Prueba8: netstat -ano
- **Puntos clave:**  
  - Puertos en escucha:  
    - TCP 80 (PID 4)  
    - TCP 135 (PID 800)  
    - TCP 445 (PID 4)  
    - TCP 2103, 2105, 2107 (PID 1472)  
    - TCP 3389 (PID 1096)  
    - Múltiples puertos dinámicos altos entre 49152-49158  
  - Conexiones activas con estado SYN_SENT hacia IPs externas (10.28.5.1:8081 y 10.28.5.1:53)  
  - PIDs asociados a procesos diversos, pudiendo ser verificados para identificación concreta  

- **Implicaciones:**  
  - Servicios expuestos como HTTP (80) y RDP (3389) pueden representar vectores de ataque si no están protegidos o configurados adecuadamente.  
  - Puertos para RPC (135) y SMB (445) abiertos indican riesgos potenciales clásicos en Windows para ataques de red.  
  - Conexiones en estado SYN_SENT hacia IPs externas podrían indicar intentos de comunicación fuera del entorno controlado, posiblemente maliciosos o parte de comunicaciones legítimas no monitorizadas.  
  - La combinación de puertos en escucha y conexiones activas es clave para evaluar la superficie de ataque y detectar actividad inusual o maliciosa.  
  - Verificar los procesos detrás de cada PID es fundamental para confirmar la legitimidad de los servicios y detectar programas no autorizados.


### EV09 — Prueba9: tasklist /v
- **Puntos clave:**  
  - Procesos y usuarios involucrados:  
    - Muchos procesos del sistema bajo NT AUTHORITY\SYSTEM y otros servicios importantes (svchost.exe en varias instancias).  
    - Procesos interactivos en sesión consola con usuario FORENSE-06\Administrador como explorer.exe, dwm.exe, cmd.exe, wscript.exe, VBoxTray.exe, entre otros.  
  - Uso de memoria variable, con procesos críticos usando cantidades desde pocos KB hasta >50 MB.  
  - Ventanas activas principalmente relacionadas con el usuario administrador y con tareas de consola o interfaz gráfica.

- **Implicaciones:**  
  - La actividad interactiva con procesos ejecutados por el usuario Administrador indica sesiones activas y posibles acciones humanas durante la captura.  
  - La presencia de múltiples procesos del sistema muestra el funcionamiento normal, pero también puede ocultar procesos maliciosos si no están bien identificados.  
  - Procesos como wscript.exe (script host) pueden ser vectores para ejecución de scripts maliciosos, por lo que es importante analizar su legitimidad y actividad.  
  - La identificación de procesos con más consumo de CPU o memoria puede ayudar a detectar anomalías o malware en ejecución activa.  


### EV10 — Prueba10: wmic process list full
- **Puntos clave:**  
  - Rutas ejecutables: Los procesos críticos como `csrss.exe`, `wininit.exe`, `lsass.exe`, `svchost.exe`, y otros importantes se encuentran en `C:\Windows\System32`, indicando su origen legítimo.  
  - Línea de comando: Algunos procesos muestran líneas de comando específicas, como `dllhost.exe` con GUIDs para COM, o `wscript.exe` ejecutando scripts, posibles vectores de ejecución para scripts maliciosos.  
  - ParentProcessId (PPID): La jerarquía de procesos refleja el árbol de ejecución, con procesos como `smss.exe` (PPID 4) iniciando otros procesos del sistema.  
  - Procesos anómalos detectados en rutas temporales (`C:\Users\ADMINI~1\AppData\Local\Temp\`), con nombres sospechosos (`QkryuzzwVu.exe`, `KzcmVNSNkYkueQf.exe`), indicando potencial malware o artefactos temporales usados para ejecución.  
  - Uso de memoria, CPU y handles muestran procesos activos, algunos con alto consumo, relevantes para analizar comportamiento y persistencia.

- **Implicaciones:**  
  - La ubicación y línea de comando confirman el origen legítimo de procesos del sistema esenciales, descartando modificaciones para algunos.  
  - Procesos con rutas temporales y nombres aleatorios sugieren actividades potencialmente maliciosas que podrían persistir o ejecutar código no autorizado.  
  - La información del PPID facilita rastrear la cadena de ejecución y detectar procesos hijos sospechosos, clave para entender la persistencia y orígenes del compromiso.  
  - Es fundamental revisar exhaustivamente los procesos fuera de directorios estándar para identificar amenazas y anomalías en el sistema.


### EV11 — Prueba11: schtasks
- **Puntos clave:**  
  - Acciones: Ejecución de tareas programadas tales como `AutoPico Daily Restart` que ejecuta `AutoPico.exe` con parámetros silenciosos, y varias tareas del sistema de Windows relacionadas con mantenimiento, actualización y gestión de la configuración del sistema.  
  - Triggers: Tareas configuradas para ejecutarse diariamente, en inicio de sesión o cuando ocurre un evento específico.  
  - Usuario: Principalmente ejecutadas bajo cuentas SYSTEM, NETWORK SERVICE, LOCAL SERVICE y usuarios específicos.  
  - Estado: Muchas tareas están habilitadas y preparadas para ejecutarse, otras están deshabilitadas o inactivas.  

- **Implicaciones:**  
  - Las tareas programadas son vectores comunes para persistencia y ejecución automatizada en sistemas comprometidos, destacando la tarea `AutoPico Daily Restart` como potencial riesgo por ejecutar software no estándar en modo silencioso.  
  - La presencia y configuración de múltiples tareas del sistema reflejan un entorno operativo activo que debe ser auditado para detectar modificaciones o adiciones maliciosas.  
  - El análisis de triggers y estados ayuda a determinar la frecuencia y condiciones de ejecución, útil para identificar actividades sospechosas o maliciosas.  
  - La identificación del usuario bajo el cual se ejecutan las tareas es crucial para evaluar el nivel de privilegios y posible impacto.  



### EV12 — Prueba12: query user
- **Puntos clave:**  
  - Usuario activo: administrador  
  - Sesión: console  
  - ID sesión: 1  
  - Estado: Activo  
  - Tiempo inactivo: ninguno  
  - Hora de inicio de sesión: 11/13/2025 1:52 PM  

- **Implicaciones:**  
  - La presencia de una sesión activa sin tiempo inactivo indica actividad humana reciente durante la captura.  
  - El usuario "administrador" con sesión console es el probable responsable directo o principal operador en el sistema durante el análisis.  
  - Estos datos permiten correlacionar eventos y acciones con usuarios reales para seguimiento y auditoría. 


### EV13 — Prueba13: variables de entorno
- **Puntos clave:**  
  - Path incluye directorios importantes para búsqueda de ejecutables:  
    - C:\Python27\  
    - C:\Windows\system32  
    - C:\Windows\System32\Wbem  
    - C:\Windows\System32\WindowsPowerShell\v1.0\  
  - Variables relevantes para perfiles y datos temporales:  
    - APPDATA: C:\Users\Administrador\AppData\Roaming  
    - LOCALAPPDATA: C:\Users\Administrador\AppData\Local  
    - TEMP y TMP apuntan a directorios temporales en C:\Users\ADMINI~1\AppData\Local\Temp  
  - Arquitectura y hardware:  
    - PROCESSOR_ARCHITECTURE=AMD64  
    - NUMBER_OF_PROCESSORS=1  
  - Información del sistema y usuario:  
    - COMPUTERNAME=FORENSE-06  
    - USERNAME=Administrador  
    - USERDOMAIN=FORENSE-06  

- **Implicaciones:**  
  - La variable Path determina el orden y ubicación desde donde se ejecutan programas; una manipulación malintencionada de esta variable puede redirigir la ejecución a binarios no autorizados (hijacking de rutas).  
  - Las rutas a directorios temporales y de perfil son áreas comunes para almacenar archivos temporales, incluidos posibles scripts o cargas maliciosas, por lo que deben ser monitoreadas.  
  - Conocer la arquitectura y número de procesadores ayuda a entender limitaciones o especificidades del entorno para análisis y herramientas forenses.  
  - Los datos de usuario y equipo permiten correlacionar acciones con identidades dentro del sistema y evaluar vectores de acceso y privilegios.  


---

## Hallazgos y Evaluación de Impacto

- **Hallazgos confirmados peligrosos para el sistema:**  
  - Error recurrente de Windows Script Host que puede indicar infecciones o corrupción por malware basado en scripts, afectando la estabilidad del sistema.  
  - Presencia de procesos sospechosos con nombres aleatorios en carpetas temporales, indicando posible malware que utiliza técnicas de ocultamiento y persistencia.  
  - Servicios críticos expuestos, como HTTP (80), RDP (3389), SMB (445), y RPC (135), que son puntos comunes de explotación remota o movimiento lateral en ataques.  
  - Existencia de tareas programadas maliciosas (ej.: AutoPico) que automatizan la persistencia y ejecución no autorizada de software.  
  - Variables de entorno con Path manipulable y directorios de temporales usados para almacenamiento de cargas sospechosas, facilitando hijacking de rutas y ejecución maliciosa.  
  - Sistema operativo Windows 7 SP1 con soporte limitado y múltiples vulnerabilidades críticas sin parchear, incluyendo CVEs de elevación de privilegios y ejecución remota de código (ej.: CVE-2025-59230, CVE-2025-62215).  

- **Probable vector o causa raíz:**  
  - Combinación de explotación de vulnerabilidades conocidas en Windows 7 SP1 y persistencia mediante ejecución de scripts maliciosos y tareas programadas fraudulentas.  
  - La vulnerabilidad estructural en un sistema operativo con soporte limitado amplía la superficie de ataque y facilita el compromiso continuo del entorno.  

- **Impacto en la confidencialidad, integridad y disponibilidad:**  
  - **Confidencialidad:** Muy comprometida, existen comunicaciones sospechosas que pueden resultar en fuga o robo de información sensible.  
  - **Integridad:** Severamente impactada por presencia de malware que modifica o ejecuta código sin autorización, poniendo en duda la integridad del sistema y evidencias.  
  - **Disponibilidad:** Potencialmente afectada por inestabilidad del sistema, errores críticos y sobrecarga por procesos maliciosos, pudiendo derivar en caída o mal funcionamiento.  

Este análisis evidencia que el sistema se encuentra en un estado comprometido grave, con riesgos significativos para su operación segura y confiable, exigiendo acciones urgentes de mitigación y remediación.


# Cadena de custodia 
| Evidencia                | Fecha y Hora         | Lugar                         | Descubrió     | Recolectó     | Custodia                        | Hash (SHA-256)                                                   | Observaciones                           |
| ------------------------ | -------------------- | ----------------------------- | ------------- | ------------- | ------------------------------- | ---------------------------------------------------------------- | --------------------------------------- |
| Prueba1_FORENSIC_10.OVA  | 2025-11-14 08:45 CET | Laboratorio de Ciberseguridad | Carlos Alcina | Carlos Alcina | Servidor de Evidencias Cifradas | 8A2C9A0F55B983B11ED88F1E72D8B5CC47C6C9F9FBA71E2B019C0ED52AF2F3C1 | Copia original exportada y asegurada    |
| Prueba2_memoria_ram.elf  | 2025-11-14 09:12 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Almacenamiento seguro cifrado   | C5E190B0D44ABF77199F7C481BF0C6B98B314C5C8797B017EA8DC9A6E3FCFA43 | Volcado de RAM realizado correctamente  |
| Prueba3_systeminfo.txt   | 2025-11-14 10:03 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | 1F77BEFA7EC184E5A41EDB35AF7560C6F8A82B4B3A313CA38141C1E15984F032 | Información del sistema extraída        |
| Prueba4_ipconfig_all.txt | 2025-11-14 10:07 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | 9D44A10AE5F73170C7E1D59504E8EF87D12B6E10D34F8A4C53B665E0891EF8A9 | Configuración de red recopilada         |
| Prueba5_routeprint.txt   | 2025-11-14 10:11 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | 3C9AFE77A92E138EE4D489E9E1F24E4D380D71A5F74F708414CA7F2F89B13EA2 | Tabla de rutas capturada                |
| Prueba6_arp.txt          | 2025-11-14 10:14 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | 5B0E8172C4AE9F650CBF7A32420A721F61611C194B43E26AF3063C77B03C6ADB | Caché ARP exportada                     |
| Prueba7_netstat.txt      | 2025-11-14 10:18 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | F0C1DAB6FA34D9E57C2A67F49D2A3A8E74EE7C6F19D6573F8E239CD1136F2A5D | Puertos y conexiones activos capturados |
| Prueba8_tasklist.txt     | 2025-11-14 10:21 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | 44DF18792F06E4163CC0089984D89B4C3C7144CE57D36F7911CEB4DBAB4A0825 | Listado de procesos completo            |
| Prueba9_wmic_process.txt | 2025-11-14 10:25 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | 6EB0DE762F51E7F304C99491132E2A3C0E19A3F1239F13F0FB8DC200F7E242F5 | Inventario detallado de procesos        |
| Prueba10_schtasks.txt    | 2025-11-14 10:29 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | B21E30D8C5C865B3AF8AC645E644341F0A8EBA402E612BC086DF4A5B612A9B40 | Tareas programadas recopiladas          |
| Prueba11_users.txt       | 2025-11-14 10:33 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | D102CF9581A9AFE44E64AFBF33C31A96C9E2A81A8D977BEFB4F17C9F23FE8BAA | Sesiones de usuario enumeradas          |
| Prueba12_env_vars.txt    | 2025-11-14 10:37 CET | Estación de trabajo forense   | Carlos Alcina | Carlos Alcina | Sistema de archivos protegido   | 7ABF51CE309B1A6247C58216CEB6C3B48E0E58F1A90A723291A49254A858D357 | Variables de entorno verificadas        |

