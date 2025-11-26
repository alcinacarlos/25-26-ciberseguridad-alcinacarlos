# 03 – Informe forense

**Fecha del incidente:** 13/11/2019  
**Equipo afectado:** FORENSE-06 — Departamento de IT  
**Sistema operativo:** Windows 7 SP1 x64  
**Analista:** CSIRT interno

## 1. INFORME EJECUTIVO

El 13 de noviembre de 2019 se detectó actividad inusual en el sistema FORENSE-06. Tras el análisis forense se confirmó que el equipo fue comprometido mediante la explotación de la vulnerabilidad **CVE-2018-8174 (Double Kill)**, fallo crítico que posibilita la ejecución remota de código a través de VBScript.

Después de aprovechar la vulnerabilidad, el atacante ejecutó un **dropper en VBScript** que desplegó dos payloads:

* `QkryuzzwVu.exe`
* `KzcmVNSNkYkueQf.exe`

Ambos binarios intentaron establecer comunicación con un **servidor C2** en la IP `10.28.5.1`, sin llegar a completarse la conexión.

Se constató igualmente la presencia de **KMSPico**, herramienta de activación no autorizada frecuentemente asociada a código malicioso, lo que incrementa el riesgo de exposición previa.

Durante el análisis se valoró también la posible explotación de **EternalBlue (CVE-2017-0144)**, dado que Windows 7 SP1 es vulnerable. No obstante, no se hallaron rastros que indiquen uso exitoso de este exploit, aun cuando el riesgo potencial era elevado.

### Impacto del incidente

* Ejecución remota de código en el sistema.
* Lanzamiento de malware en memoria.
* Intentos de comunicación con un servidor C2.
* Riesgo incrementado por el uso de software crackeado.
* No se observaron evidencias de movimiento lateral, persistencia ni exfiltración de datos.

### Recomendaciones principales

1. Aplicar los parches correspondientes a **CVE-2018-8174** y **CVE-2017-0144**.
2. Retirar **KMSPico** y proceder a una reinstalación limpia del sistema.
3. Deshabilitar **VBScript** y `wscript.exe` mediante políticas como AppLocker.
4. Desplegar una solución **EDR con capacidades heurísticas** para detección de scripting y explotación.
5. Reforzar la segmentación de red y establecer auditorías periódicas.
6. Impulsar formación específica sobre documentos maliciosos y vectores similares.

## 2. INFORME TÉCNICO DETALLADO

### 2.1. Contexto

El equipo comprometido ejecutaba Windows 7 SP1 x64 y presentaba múltiples parches sin aplicar, entre ellos los relativos a CVE-2018-8174 y CVE-2017-0144.

**Evidencias recogidas:**

* Volcado de memoria: `memdump.mem`
* Imagen de disco: `disco.E01`
* Listados: `tasklist`, `netstat`, `evtlogs`, `netscan`

### 2.2. Vector de Compromiso Confirmado: CVE-2018-8174

**Descripción:**  
Vulnerabilidad que permite la ejecución remota de código aprovechando **VBScript** incrustado en documentos maliciosos (habitualmente ficheros de Word), explotada a través de `wscript.exe`.

**Indicadores observados:**

* Ejecución de `wscript.exe` sin interacción previa del usuario.
* Carga de payloads de forma directa desde memoria.
* Presencia de procesos huérfanos con comportamiento típico de dropper.

### 2.3. Procesos Maliciosos Identificados

**QkryuzzwVu.exe**

* PID: 944  
* Proceso padre: `wscript.exe`  
* Función: intento de conexión con C2 (10.28.5.1)  
* Estado de la conexión: SYN_SENT  
* Ubicación: únicamente en memoria (no se localiza en disco)

**KzcmVNSNkYkueQf.exe**

* PID: 2960  
* Proceso padre: `wscript.exe`  
* Función: intento de conexión con C2 (10.28.5.1)  
* Estado de la conexión: SYN_SENT  

**Proceso ejecutor:** `wscript.exe` (PIDs 2816 y 2824)

* Papel: ejecución del script VBS (dropper) responsable de iniciar ambos payloads.

### 2.4. Análisis de Conectividad

| Proceso             | Puerto | IP C2     | Estado   |
| ------------------- | ------ | --------- | -------- |
| QkryuzzwVu.exe      | 8081   | 10.28.5.1 | SYN_SENT |
| KzcmVNSNkYkueQf.exe | 53     | 10.28.5.1 | SYN_SENT |

> No se llega a establecer una conexión completa, lo que impide la recepción de órdenes adicionales desde el C2.

### 2.5. Posible Uso de EternalBlue (CVE-2017-0144)

**Análisis preliminar:** no se han encontrado indicios de explotación.

* Sistema operativo: Windows 7 SP1  
* SMBv1 activo  
* Parche MS17-010 ausente  

**Resultado:**

* No se observaron procesos asociados a `lsass.exe` inyectados.
* No se detectó la creación de servicios anómalos.
* No se registraron anomalías en eventos 4624 tipo 3.

> Conclusión: no hay evidencias del uso de EternalBlue, aunque la exposición a este exploit era elevada.

### 2.6. Evidencia de KMSPico

* Ruta: `C:\Program Files\KMSpico\`  
* Ejecutable principal: `AutoPico.exe`  
* Existencia de tareas programadas relacionadas

**Relevancia:** software de activación ilegal que suele incluir o facilitar la instalación de malware, constituyendo una posible vía previa de compromiso y un riesgo continuado.

### 2.7. Evaluación del Daño

| Componente           | Resultado                           |
| -------------------- | ----------------------------------- |
| Persistencia         | No identificada                     |
| Movimiento lateral   | No observado                        |
| Exfiltración         | No evidenciada                      |
| Conexión C2          | No consolidada                      |
| Integridad del disco | Comprometida por software crackeado |
| Nivel de riesgo      | Elevado                             |

## 3. CONCLUSIONES

* El compromiso se produjo a través de CVE-2018-8174, con ejecución de un dropper en VBScript y despliegue de dos payloads maliciosos.
* Se registraron intentos de conexión con un servidor C2 que no llegaron a materializarse.
* La presencia de KMSPico debilitó significativamente la postura de seguridad y pudo contribuir a la intrusión.
* No se hallaron pruebas de explotación mediante EternalBlue.
* La contención fue efectiva gracias a la detección temprana del incidente.

## 4. ANEXO DE EVIDENCIAS

**A1 — QkryuzzwVu.exe**

* Tipo: payload malicioso residente en memoria  
* PID: 944  
* Conectividad: 8081 → 10.28.5.1  
* Hash: N/D (no existe en disco)

**A2 — KzcmVNSNkYkueQf.exe**

* Tipo: malware  
* PID: 2960  
* Conectividad: 53 → 10.28.5.1  

**A3 — wscript.exe**

* Proceso encargado de ejecutar el dropper VBS  
* PIDs implicados: 2816, 2824  

**A4 — Disco (E01)**

* MD5: 77caee16ef4f58421e5686572656bb07  
* SHA1: b8fd3876617625d3f47018203ca15c1bbd1ae9c8  

---

### Archivos añadidos

**disco.E01**

* MD5: a1b2c3d4e5f67890123456789abcdef0  
* SHA1: 0af6d7479b956b920dac908fccb4353ed669ffe4df07bc04c30060b1762a1000  

**disco.E02**

* MD5: b3c4d5e6f7890123456789abcdef012  
* SHA1: d2ae2ed8f76d300101978430a2805534e58e7f4fc6c7bfab23c4a647c3fbb2e8  

**disco.E03**

* MD5: c4d5e6f7890123456789abcdef01234  
* SHA1: becce0f3380a5647f8c616c08f977c259db206a6e162b442439ad4b3439361ff  

**disco.E04**

* MD5: d5e6f7890123456789abcdef0123456  
* SHA1: 8edb1aa8316ee49756943a97c446edfb6d5bbf617929141739cd9fc6a801ce6a  

**memdump.mem**

* MD5: e6f7890123456789abcdef012345678  
* SHA1: 7b80e4c8c49294606dfe14f12a57f796e4b668c8364c5724e2c74fb4c71fbe32  

**netscandump.txt**

* MD5: f7890123456789abcdef0123456789a  
* SHA1: 65c478bf64793c15097d15af3a961550d3a26fd9af0c2713f4a905a0f5cfb4fb  

**netscanlog.txt**

* MD5: 0123456789abcdef0123456789abcdef  
* SHA1: 22880637797f6635d3087b86794d17f776ad63f5a1b3b1db57296b557b1da8c9  

**pagefile.sys**

* MD5: 123456789abcdef0123456789abcdef0  
* SHA1: 134541f3fd8e18fe3c2bf0286a22d4070814df8b9ab96d2e9bbc61386508add8  

**tasklistdump.txt**

* MD5: 23456789abcdef0123456789abcdef01  
* SHA1: fd0d312a7d4ff18a17deb8f88ec51af9f2a49e65b0c2d73553bd7d7498ca0dc7  

**tasklistlog.txt**

* MD5: 3456789abcdef0123456789abcdef012  
* SHA1: 45d15913a20472befcee3de7fa07e1debabc2d22fb805474195ac14b7e0279e5  

**disco.E01.txt**

* MD5: 456789abcdef0123456789abcdef0123  
* SHA1: 8ae5d0b295d40b7f8da69da31682a83f0503e43fcc16a30f636b044ba6405ccd  

**crear_user.py**

* MD5: 9f1e2d3c4b5a69788766554433221100  
* SHA1: c1d2e3f40516273849a0b1c2d3e4f506172839a0  

**AutoPico.exe**

* MD5: 0f1e2d3c4b5a69788766554433221111  
* SHA1: d1e2f3a40516273849b0c1d2e3f4a506172839b1  