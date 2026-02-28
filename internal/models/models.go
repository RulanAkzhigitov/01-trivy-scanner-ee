package models

import (
	"database/sql"
	"time"
)

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

type Package struct {
    ID      int
    ScanID  int
    Name    string
    Version string
    Arch    string
}