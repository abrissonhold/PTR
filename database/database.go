package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// DBClient maneja las operaciones de persistencia en MySQL.
type DBClient struct {
	db *sql.DB
}

// NewDBClient inicializa y verifica la conexion a la base de datos MySQL.
func NewDBClient(dsn string) (*DBClient, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("error al abrir conexion MySQL: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("error al hacer ping a MySQL: %w", err)
	}

	client := &DBClient{db: db}
	if err := client.initTables(); err != nil {
		log.Printf("[DATABASE WARN] No se pudieron verificar/crear tablas automaticamente: %v", err)
	}

	log.Println("[DATABASE] Conexion exitosa con servidor MySQL.")
	return client, nil
}

// Close cierra la conexion a la base de datos de forma segura.
func (c *DBClient) Close() error {
	if c != nil && c.db != nil {
		return c.db.Close()
	}
	return nil
}

// initTables asegura que las tablas existan si la base de datos esta disponible.
func (c *DBClient) initTables() error {
	if c == nil || c.db == nil {
		return nil
	}
	queries := []string{
		`CREATE TABLE IF NOT EXISTS historial_ips (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			ip_origen VARCHAR(45) NOT NULL UNIQUE,
			primera_deteccion DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
			ultima_deteccion DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
			total_bloqueos INT NOT NULL DEFAULT 0,
			estado_actual VARCHAR(20) NOT NULL DEFAULT 'NORMAL',
			INDEX idx_ip (ip_origen),
			INDEX idx_estado (estado_actual)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

		`CREATE TABLE IF NOT EXISTS registros_trafico (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			timestamp DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
			ip_origen VARCHAR(45) NOT NULL,
			paquetes_por_segundo INT NOT NULL,
			es_amenaza BOOLEAN NOT NULL DEFAULT FALSE,
			INDEX idx_ip_origen (ip_origen),
			INDEX idx_timestamp (timestamp),
			INDEX idx_es_amenaza (es_amenaza)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

		`CREATE TABLE IF NOT EXISTS eventos_bloqueo (
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
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,
	}

	for _, q := range queries {
		if _, err := c.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// RecordTraffic inserta un registro con los paquetes por segundo medidos para una IP.
func (c *DBClient) RecordTraffic(ip string, pps int, isThreat bool) error {
	if c == nil || c.db == nil {
		return nil
	}

	query := `INSERT INTO registros_trafico (timestamp, ip_origen, paquetes_por_segundo, es_amenaza)
	          VALUES (?, ?, ?, ?)`
	_, err := c.db.Exec(query, time.Now(), ip, pps, isThreat)
	if err != nil {
		return fmt.Errorf("error guardando registro de trafico: %w", err)
	}

	// Actualizar o crear registro en historial_ips
	status := "NORMAL"
	if isThreat {
		status = "AMENAZA"
	}
	upsertHistorial := `INSERT INTO historial_ips (ip_origen, primera_deteccion, ultima_deteccion, estado_actual)
	                    VALUES (?, ?, ?, ?)
	                    ON DUPLICATE KEY UPDATE ultima_deteccion=?, estado_actual=?`
	now := time.Now()
	_, _ = c.db.Exec(upsertHistorial, ip, now, now, status, now, status)

	return nil
}

// RecordBlockEvent registra un evento de bloqueo para una IP origen y incrementa el conteo en historial_ips.
func (c *DBClient) RecordBlockEvent(ip string, pps int, blockSeconds int) (int64, error) {
	if c == nil || c.db == nil {
		return 0, nil
	}

	query := `INSERT INTO eventos_bloqueo (timestamp_inicio, ip_origen, pps_detectados, duracion_segundos, estado)
	          VALUES (?, ?, ?, ?, 'ACTIVO')`
	res, err := c.db.Exec(query, time.Now(), ip, pps, blockSeconds)
	if err != nil {
		return 0, fmt.Errorf("error al registrar evento de bloqueo: %w", err)
	}

	eventID, err := res.LastInsertId()
	if err != nil {
		eventID = 0
	}

	// Incrementar total_bloqueos en historial_ips
	updateHistorial := `UPDATE historial_ips SET total_bloqueos = total_bloqueos + 1, estado_actual = 'BLOQUEADO' WHERE ip_origen = ?`
	_, _ = c.db.Exec(updateHistorial, ip)

	return eventID, nil
}

// RecordUnblockEvent actualiza el estado del evento de bloqueo a 'LIBERADO' y su timestamp_fin.
func (c *DBClient) RecordUnblockEvent(ip string, eventID int64) error {
	if c == nil || c.db == nil {
		return nil
	}

	now := time.Now()
	if eventID > 0 {
		query := `UPDATE eventos_bloqueo SET timestamp_fin = ?, estado = 'LIBERADO' WHERE id = ?`
		_, err := c.db.Exec(query, now, eventID)
		if err != nil {
			log.Printf("[DATABASE WARN] Error actualizando evento_bloqueo id %d: %v", eventID, err)
		}
	} else {
		query := `UPDATE eventos_bloqueo SET timestamp_fin = ?, estado = 'LIBERADO' WHERE ip_origen = ? AND estado = 'ACTIVO'`
		_, _ = c.db.Exec(query, now, ip)
	}

	updateHistorial := `UPDATE historial_ips SET estado_actual = 'NORMAL' WHERE ip_origen = ?`
	_, _ = c.db.Exec(updateHistorial, ip)

	return nil
}
