package repo

import (
	"database/sql"
	"time"
	"trivy-scanner-ee/internal/models"
)

type ScanRepo struct {
	db *sql.DB
}

func NewScanRepo(db *sql.DB) *ScanRepo {
	return &ScanRepo{db: db}
}

func (r *ScanRepo) CreateScan(scanType, target string) (int, error) {
	var id int
	err := r.db.QueryRow(`
        INSERT INTO scans (type, target, status, created_at)
        VALUES ($1, $2, 'pending', NOW())
        RETURNING id
    `, scanType, target).Scan(&id)
	return id, err
}

func (r *ScanRepo) GetScan(id int) (*models.Scan, error) {
	var s models.Scan
	err := r.db.QueryRow(`
        SELECT id, type, target, status, created_at, started_at, finished_at, error
        FROM scans WHERE id = $1
    `, id).Scan(&s.ID, &s.Type, &s.Target, &s.Status, &s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.Error)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *ScanRepo) UpdateScanStatus(id int, status string, startedAt, finishedAt *time.Time, errMsg string) error {
	_, err := r.db.Exec(`
        UPDATE scans
        SET status = $1, started_at = $2, finished_at = $3, error = $4
        WHERE id = $5
    `, status, startedAt, finishedAt, errMsg, id)
	return err
}

func (r *ScanRepo) SaveVulnerabilities(scanID int, vulns []models.Vulnerability) error {
	for _, v := range vulns {
		_, err := r.db.Exec(`
            INSERT INTO vulnerabilities (scan_id, vuln_id, package, installed_version, fixed_version, severity, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, scanID, v.VulnerabilityID, v.Package, v.InstalledVersion, v.FixedVersion, v.Severity, v.Description)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *ScanRepo) SavePackages(scanID int, pkgs []models.Package) error {
	for _, p := range pkgs {
		_, err := r.db.Exec(`
            INSERT INTO packages (scan_id, name, version, arch)
            VALUES ($1, $2, $3, $4)
        `, scanID, p.Name, p.Version, p.Arch)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetVulnerabilities возвращает все уязвимости для указанного scanID
func (r *ScanRepo) GetVulnerabilities(scanID int) ([]models.Vulnerability, error) {
	rows, err := r.db.Query(`
        SELECT id, scan_id, vuln_id, package, installed_version, fixed_version, severity, description
        FROM vulnerabilities
        WHERE scan_id = $1
        ORDER BY severity, vuln_id
    `, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []models.Vulnerability
	for rows.Next() {
		var v models.Vulnerability
		err := rows.Scan(&v.ID, &v.ScanID, &v.VulnerabilityID, &v.Package,
			&v.InstalledVersion, &v.FixedVersion, &v.Severity, &v.Description)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// GetPackages возвращает все пакеты для указанного scanID
func (r *ScanRepo) GetPackages(scanID int) ([]models.Package, error) {
	rows, err := r.db.Query(`
        SELECT id, scan_id, name, version, arch
        FROM packages
        WHERE scan_id = $1
        ORDER BY name
    `, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pkgs []models.Package
	for rows.Next() {
		var p models.Package
		err := rows.Scan(&p.ID, &p.ScanID, &p.Name, &p.Version, &p.Arch)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}
