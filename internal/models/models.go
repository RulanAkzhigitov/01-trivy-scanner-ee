package models

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// JSONField для полей JSONB в PostgreSQL
type JSONField map[string]interface{}

// Value реализует интерфейс driver.Valuer для JSONField
func (j JSONField) Value() (driver.Value, error) {
	return json.Marshal(j)
}

// Scan реализует интерфейс sql.Scanner для JSONField
func (j *JSONField) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal JSONB value: %v", value)
	}
	return json.Unmarshal(bytes, j)
}

// Scan - основная модель для сканирования (существующая)
type Scan struct {
	ID         int
	Type       string // "image" или "file"
	Target     string // образ или путь к файлу
	Status     string // pending, running, completed, failed
	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	Error      sql.NullString
}

// Vulnerability - модель уязвимости (существующая)
type Vulnerability struct {
	ID               int
	ScanID           int
	VulnerabilityID  string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	Description      string
}

// Package - модель пакета (существующая)
type Package struct {
	ID      int
	ScanID  int
	Name    string
	Version string
	Arch    string
}

// ScanConfig - конфигурация сканирования (новая)
type ScanConfig struct {
	ID                  int
	Name                string
	Description         string
	TargetType          string   // "image", "filesystem"
	TargetPattern       string   // паттерн образа, например "harbor.*/frontend:*"
	Scanners            []string // ["vuln", "secret", "misconfig", "license"]
	ImageConfigScanners []string // ["misconfig", "secret"] для сканирования метаданных
	Severity            []string // ["UNKNOWN","LOW","MEDIUM","HIGH","CRITICAL"]
	IgnoreUnfixed       bool
	DetectionPriority   string    // "precise" или "comprehensive"
	PkgTypes            []string  // ["os", "library"]
	PkgRelationships    []string  // ["root", "direct", "indirect", "unknown"]
	RegistryAuth        JSONField // данные для аутентификации в registry
	IgnoreFile          string    // содержимое файла .trivyignore или путь к нему
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ScanJob - задание на сканирование (новая)
type ScanJob struct {
	ID         int
	ConfigID   *int      // ссылка на ScanConfig
	Name       string    // копируется из конфига для удобства
	Status     string    // "pending", "running", "completed", "failed", "stopped"
	Target     string    // конкретный образ (разрешенный из паттерна)
	Parameters JSONField // полный набор параметров для запуска Trivy
	PID        int       // ID процесса для возможности остановки
	StartedAt  *time.Time
	FinishedAt *time.Time
	Error      sql.NullString
	CreatedAt  time.Time
}

// ScanResult - результат сканирования (новая)
type ScanResult struct {
	ID         int
	JobID      int
	ResultType string    // "vuln", "misconfig", "secret", "license"
	Target     string    // цель внутри отчета (например, имя файла)
	Class      string    // "os-pkgs", "library" и т.д.
	Data       JSONField // полный JSON объекта Results из Trivy
}

// ScanGroup - группа сканирований (новая)
type ScanGroup struct {
	ID          int
	Name        string
	Description string
	ConfigIDs   []int  // массив ID конфигураций, входящих в группу
	Schedule    string // cron-выражение
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ScheduleRecord - запись о выполнении по расписанию (новая)
type ScheduleRecord struct {
	ID          int
	GroupID     int
	JobIDs      []int // созданные задания
	ScheduledAt time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
	Status      string // "pending", "running", "completed", "failed"
}

// Для удобной работы с массивами в БД можно добавить вспомогательные функции,
// но они пока не требуются, так как мы используем pq.Array
