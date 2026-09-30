-- ==============================================================================
-- Sistema de Prevencion de Intrusos (IPS) en Tiempo Real - Mitigacion DoS
-- Esquema de Base de Datos MySQL
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS ips_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE ips_db;

-- ------------------------------------------------------------------------------
-- Tabla: historial_ips
-- Almacena el perfil acumulado de las direcciones IP observadas en la red.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS historial_ips (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_origen VARCHAR(45) NOT NULL UNIQUE,
    primera_deteccion DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ultima_deteccion DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    total_bloqueos INT NOT NULL DEFAULT 0,
    estado_actual VARCHAR(20) NOT NULL DEFAULT 'NORMAL',
    INDEX idx_ip (ip_origen),
    INDEX idx_estado (estado_actual)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------------------------
-- Tabla: registros_trafico
-- Almacena las mediciones de volumen de trafico (pps) por IP origen.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS registros_trafico (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ip_origen VARCHAR(45) NOT NULL,
    paquetes_por_segundo INT NOT NULL,
    es_amenaza BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX idx_ip_origen (ip_origen),
    INDEX idx_timestamp (timestamp),
    INDEX idx_es_amenaza (es_amenaza)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------------------------
-- Tabla: eventos_bloqueo
-- Registra cada evento de mitigacion/bloqueo de IP, duracion y su estado.
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eventos_bloqueo (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp_inicio DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    timestamp_fin DATETIME(3) NULL,
    ip_origen VARCHAR(45) NOT NULL,
    pps_detectados INT NOT NULL,
    duracion_segundos INT NOT NULL DEFAULT 15,
    estado VARCHAR(20) NOT NULL DEFAULT 'ACTIVO',
    motivo VARCHAR(255) NOT NULL DEFAULT 'Exceso de paquetes por segundo (Ataque DoS)',
    INDEX idx_ip_bloqueo (ip_origen),
    INDEX idx_estado_bloqueo (estado),
    INDEX idx_timestamp_inicio (timestamp_inicio)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
