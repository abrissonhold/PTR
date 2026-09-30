# Guía de Despliegue y Pruebas del IPS en Tiempo Real (Mitigación DoS)

Este documento detalla los pasos completos para instalar, configurar, ejecutar y probar el **Sistema de Prevención de Intrusos (IPS) en Tiempo Real** desarrollado en Go para la mitigación de ataques DoS.

---

## 1. Requisitos Previos e Instalación de Dependencias (Kali Linux / Servidor IPS)

En la máquina servidor (Kali Linux), instala las herramientas del sistema y librerías de captura de red requeridas:

```bash
# Actualizar lista de paquetes
sudo apt-get update

# Instalación de Go (en caso de no tenerlo instalado)
sudo apt-get install -y golang-go

# Instalación de la librería de captura de tráfico libpcap y herramientas de red
sudo apt-get install -y libpcap-dev iptables net-tools

# Instalación del servidor MySQL / MariaDB
sudo apt-get install -y mariadb-server mariadb-client
```

---

## 2. Configuración de la Base de Datos MySQL

1. Inicia y habilita el servicio de MySQL / MariaDB:

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

2. Crea la base de datos y la estructura ejecutando el script `schema.sql`:

```bash
sudo mysql -u root < schema.sql
```

3. (Opcional) Verifica las tablas creadas:

```bash
sudo mysql -u root -e "USE ips_db; SHOW TABLES;"
```

Deberás ver las siguientes 3 tablas:
- `historial_ips`
- `registros_trafico`
- `eventos_bloqueo`

---

## 3. Compilación del Código Fuente en Go

Ubicado en la carpeta raíz del proyecto, compila el ejecutable del IPS:

```bash
# Descargar dependencias del proyecto
go mod download

# Compilar el binario ejecutable
go build -o ips main.go
```

---

## 4. Configuración de Variables de Entorno (Opcional)

El IPS cuenta con valores predeterminados listos para funcionar:
- **Interfaz de red (`IPS_INTERFACE`):** `eth0` (por defecto)
- **Umbral DoS (`IPS_THRESHOLD_PPS`):** `40` paquetes por segundo
- **Duración del Bloqueo (`IPS_BLOCK_DURATION_SECONDS`):** `15` segundos
- **Herramienta Firewall (`IPS_FIREWALL_TOOL`):** `iptables`
- **DSN MySQL (`IPS_MYSQL_DSN`):** `root:rootpassword@tcp(127.0.0.1:3306)/ips_db?parseTime=true`

Si deseas personalizar la interfaz o las credenciales antes de ejecutar, exporta las variables:

```bash
export IPS_INTERFACE="eth0"
export IPS_THRESHOLD_PPS=40
export IPS_BLOCK_DURATION_SECONDS=15
export IPS_FIREWALL_TOOL="iptables"
export IPS_MYSQL_DSN="root:@tcp(127.0.0.1:3306)/ips_db?parseTime=true"
```

---

## 5. Ejecución del IPS en Kali Linux

Debido a que la captura de tráfico a bajo nivel mediante `libpcap` y las reglas de `iptables` requieren privilegios de red elevados, ejecuta el binario con `sudo`:

```bash
sudo ./ips
```

O si prefieres ejecutar directamente con el comando `go run`:

```bash
sudo IPS_INTERFACE=eth0 go run main.go
```

Verás una salida formateada en la terminal indicando que el IPS está escuchando en tiempo real.

---

## 6. Simulación de Ataque DoS desde Ubuntu y Verificación de Mitigación

### A. Preparación del Atacante (Ubuntu)

En la máquina atacante (Ubuntu), instala la herramienta `hping3`:

```bash
sudo apt-get update
sudo apt-get install -y hping3
```

### B. Generación de Tráfico Normal (Tráfico Seguro)

Envía un ping normal a la IP de Kali Linux (ejemplo: `192.168.1.150`):

```bash
ping 192.168.1.150
```

*Resultado esperado:* La tasa será de 1 paquete por segundo. El IPS **no** aplicará bloqueo.

### C. Lanzamiento del Ataque DoS (Pico superior a 40 pps)

Genera una ráfaga de paquetes SYN/UDP que supere el umbral de 40 pps hacia la IP del servidor IPS:

```bash
# Ataque SYN Flood masivo
sudo hping3 -S --flood -p 80 192.168.1.150
```

O enviando un número rápido de paquetes por segundo (ej. 100 paquetes por segundo):

```bash
sudo hping3 -S --fast -c 100 -p 80 192.168.1.150
```

### D. Verificación del Comportamiento en el IPS (Kali Linux)

1. **Alertas en Consola:**
   - La terminal del IPS mostrará inmediatamente una alerta roja `[AMENAZA DoS DETECTADA]`.
   - A continuación, una alerta amarilla `[MITIGACIÓN AUTOMÁTICA]` informando que la IP ofensora ha sido agregada a `iptables` por **15 segundos**.

2. **Verificación de la regla en iptables:**
   Abre una nueva terminal en Kali Linux y ejecuta:
   ```bash
   sudo iptables -L INPUT -v -n
   ```
   Observará la regla `DROP` activa para la IP atacante.

3. **Verificación del Desbloqueo Automático (15 segundos):**
   - Exactamente 15 segundos después, en la consola del IPS aparecerá el mensaje en verde `[RESTABLECIMIENTO ACCESO]` confirmando que la regla fue removida automáticamente.
   - Si ejecutas nuevamente `sudo iptables -L INPUT -v -n`, la regla ya no estará presente.

4. **Consulta de Auditoría en la Base de Datos MySQL:**
   Conéctate a la base de datos para auditar los incidentes registrados:

   ```sql
   -- Ver eventos de bloqueo registrados
   SELECT * FROM ips_db.eventos_bloqueo;

   -- Ver registros de tráfico por segundo
   SELECT * FROM ips_db.registros_trafico WHERE es_amenaza = TRUE;

   -- Ver el historial de IPs detectadas y estado
   SELECT * FROM ips_db.historial_ips;
   ```
