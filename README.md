# 🛡️ Sistema de Prevención de Intrusos (IPS) en Tiempo Real - Mitigación DoS

Este proyecto es un **Sistema de Prevención de Intrusos (IPS)** desarrollado en **Go (Golang)** diseñado para escuchar el tráfico de red en tiempo real, detectar ataques de Denegación de Servicio (DoS) basados en un umbral de paquetes por segundo (pps), ejecutar bloqueos temporales automáticos en el Firewall (`iptables`) y auditar los incidentes en una base de datos **MySQL**.

---

## 🚀 Guía Paso a Paso para Usar el Proyecto (¡Apto para Todo Público!)

Sigue esta guía detallada paso a paso para configurar el entorno, levantar el servidor MySQL, ejecutar el IPS en **Kali Linux** y simular el ataque DoS desde **Ubuntu**.

---

### Paso 1: Configurar el Entorno en Kali Linux (Servidor IPS)

Abre la terminal en tu máquina **Kali Linux** y ejecuta los siguientes comandos:

#### 1.1. Actualizar e instalar dependencias necesarias
Asegúrate de tener instalados **Go**, las librerías de captura de paquetes **libpcap** y el servidor **MySQL / MariaDB**:

```bash
# 1. Actualizar el gestor de paquetes
sudo apt update

# 2. Instalar Lenguaje Go
sudo apt install -y golang

# 3. Instalar librerías de captura de red y herramientas de firewall
sudo apt install -y libpcap-dev iptables net-tools

# 4. Instalar servidor y cliente MySQL / MariaDB
sudo apt install -y mariadb-server mariadb-client
```

---

### Paso 2: Iniciar MySQL e Importar la Base de Datos

#### 2.1. Iniciar el servicio MySQL
```bash
sudo service mysql start
```
*(También puedes usar `sudo systemctl start mariadb`)*

#### 2.2. Importar la estructura de la base de datos
Dentro de la carpeta raíz del proyecto donde se encuentra el archivo `schema.sql`, ejecuta:

```bash
sudo mysql -u root < schema.sql
```

#### 2.3. Verificar que la base de datos y las tablas se crearon correctamente
Ejecuta el siguiente comando para listar las tablas:

```bash
sudo mysql -u root -e "USE ips_db; SHOW TABLES;"
```

Deberás ver las siguientes 3 tablas:
- `eventos_bloqueo`
- `historial_ips`
- `registros_trafico`

---

### Paso 3: Identificar la Interfaz de Red y la IP de Kali Linux

Antes de correr el IPS, necesitas saber cuál es la interfaz de red (ej. `eth0`, `wlan0`, `ens33`) y la dirección IP de tu máquina Kali:

```bash
ip a
```
*Ejemplo de salida:*
Si tu interfaz es `eth0` y tu IP es `192.168.1.150`, anota estos valores.

---

### Paso 4: Compilar y Ejecutar el IPS con Permisos de Superusuario

⚠️ **¿Por qué se requiere `sudo`?**
El IPS captura paquetes directamente de la placa de red a bajo nivel (usando `pcap`) y modifica dinámicamente las reglas del firewall del sistema (`iptables`). Por lo tanto, **SIEMPRE debe ejecutarse como root/sudo**.

#### Opción A: Compilar el ejecutable y correr el binario (Recomendado)
```bash
# 1. Compilar el proyecto en Go
go build -o ips main.go

# 2. Ejecutar con permisos sudo
sudo ./ips
```

#### Opción B: Ejecutar directamente con `go run`
```bash
sudo IPS_INTERFACE=eth0 go run main.go
```

*(Si tu interfaz de red es distinta a `eth0`, por ejemplo `ens33`, ejecuta: `sudo IPS_INTERFACE=ens33 ./ips`)*

Verás el banner ASCII del IPS en la terminal y el mensaje:
`[IPS] Sistema de Prevención de Intrusos ACTIVO. Escuchando en 'eth0'...`

---

### Paso 5: Probar la Simulación del Ataque DoS desde Ubuntu (Atacante)

Ve a tu máquina virtual de **Ubuntu** (el entorno del atacante).

#### 5.1. Instalar la herramienta `hping3`
```bash
sudo apt update
sudo apt install -y hping3
```

#### 5.2. Probar tráfico normal (Sin bloqueo)
Envía un ping normal hacia la IP de Kali Linux (reemplaza `<IP_DE_KALI>` por tu IP real, ej: `192.168.1.150`):

```bash
ping <IP_DE_KALI>
```
*Resultado esperado:* El tráfico es normal (1 paquete por segundo) y el IPS no aplicará ninguna restricción.

#### 5.3. Lanzar Ataque DoS para Superar el Umbral (40 pps)

El IPS está configurado con un umbral de **40 paquetes por segundo (pps)**. Para superar este umbral, ejecuta alguno de los siguientes ataques desde Ubuntu:

##### Ataque Opción 1: Envío Rápido Controlado (Supera 40 pps)
```bash
# Envía paquetes TCP SYN cada 10.000 microsegundos (~100 pps)
sudo hping3 -i u10000 -S -p 80 <IP_DE_KALI>
```

##### Ataque Opción 2: Ataque SYN Flood Masivo
```bash
sudo hping3 --flood --rand-source -p 80 <IP_DE_KALI>
```

---

### Paso 6: Verificación de Resultados y Auditoría en Tiempo Real

#### 6.1. ¿Qué verás en la Terminal de Kali Linux (Servidor IPS)?
1. **Alerta en Rojo:** Se imprimirá en pantalla `[AMENAZA DoS DETECTADA]` con la IP origen y la cantidad de pps detectados (ej. `100 pps > 40 pps`).
2. **Mitigación Automática en Amarillo:** Se mostrará `[MITIGACION AUTOMATICA]` indicando que la IP atacante fue bloqueada automáticamente en `iptables`.
3. **Desbloqueo Automático (15 Segundos Después) en Verde:** Pasados exactamente 15 segundos, se imprimirá `[RESTABLECIMIENTO ACCESO]` informando que la regla de bloqueo fue removida del firewall y el tráfico se ha restablecido.

#### 6.2. Verificar la Regla en `iptables`
Mientras el bloqueo esté activo (durante los 15 segundos), puedes abrir otra terminal en Kali Linux y comprobar la regla ejecutando:

```bash
sudo iptables -L INPUT -v -n
```
Verás una regla `DROP` activa que descarta todo el tráfico entrante de la IP del atacante. Transcurridos los 15 segundos, la regla desaparecerá automáticamente.

#### 6.3. Verificar los Registros de Auditoría en MySQL
Para verificar que los eventos se guardaron en la base de datos, conéctate a MySQL:

```sql
sudo mysql -u root -e "SELECT * FROM ips_db.eventos_bloqueo;"
```

También puedes consultar las otras tablas:
```sql
-- Historial acumulado de IPs y su estado actual
sudo mysql -u root -e "SELECT * FROM ips_db.historial_ips;"

-- Mediciones de tráfico registradas por segundo
sudo mysql -u root -e "SELECT * FROM ips_db.registros_trafico WHERE es_amenaza = TRUE;"
```

---

## 🛠️ Arquitectura y Estructura del Código Fuente

- `main.go`: Punto de entrada de la aplicación, manejo de señales e interfaz de consola.
- `config/`: Carga de parámetros configurables (interfaz, umbral PPS, tiempo de bloqueo, DSN MySQL).
- `detector/`: Motor de captura `gopacket/pcap`, colas concurrentes y evaluador de umbral de ventana deslizante.
- `firewall/`: Administrador de comandos de firewall (`iptables` / `nftables` / `mock`) con temporizador asíncrono para auto-desbloqueo de 15s.
- `database/`: Conector y capa de persistencia para MySQL (`eventos_bloqueo`, `registros_trafico`, `historial_ips`).
- `schema.sql`: Script de creación del esquema relacional en MySQL.
- `DEPLOYMENT.md`: Guía técnica adicional de despliegue.
