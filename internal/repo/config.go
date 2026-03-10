package repo

import (
	"database/sql"
	"trivy-scanner-ee/internal/models"

	"github.com/lib/pq"
)

type ConfigRepo struct {
	db *sql.DB
}

func NewConfigRepo(db *sql.DB) *ConfigRepo {
	return &ConfigRepo{db: db}
}

func (r *ConfigRepo) Create(cfg *models.ScanConfig) (int, error) {
	var id int
	err := r.db.QueryRow(`
		INSERT INTO scan_configs (
			name, description, target_type, target_pattern,
			scanners, image_config_scanners, severity, ignore_unfixed,
			detection_priority, pkg_types, pkg_relationships,
			registry_auth, ignore_file, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
		RETURNING id
	`,
		cfg.Name, cfg.Description, cfg.TargetType, cfg.TargetPattern,
		pq.Array(cfg.Scanners), pq.Array(cfg.ImageConfigScanners), pq.Array(cfg.Severity),
		cfg.IgnoreUnfixed, cfg.DetectionPriority, pq.Array(cfg.PkgTypes), pq.Array(cfg.PkgRelationships),
		cfg.RegistryAuth, cfg.IgnoreFile,
	).Scan(&id)
	return id, err
}

func (r *ConfigRepo) GetByID(id int) (*models.ScanConfig, error) {
	var cfg models.ScanConfig
	var scanners, imageScanners, severity, pkgTypes, pkgRels []string
	err := r.db.QueryRow(`
		SELECT id, name, description, target_type, target_pattern,
		       scanners, image_config_scanners, severity, ignore_unfixed,
		       detection_priority, pkg_types, pkg_relationships,
		       registry_auth, ignore_file, created_at, updated_at
		FROM scan_configs WHERE id = $1
	`, id).Scan(
		&cfg.ID, &cfg.Name, &cfg.Description, &cfg.TargetType, &cfg.TargetPattern,
		pq.Array(&scanners), pq.Array(&imageScanners), pq.Array(&severity),
		&cfg.IgnoreUnfixed, &cfg.DetectionPriority, pq.Array(&pkgTypes), pq.Array(&pkgRels),
		&cfg.RegistryAuth, &cfg.IgnoreFile, &cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	cfg.Scanners = scanners
	cfg.ImageConfigScanners = imageScanners
	cfg.Severity = severity
	cfg.PkgTypes = pkgTypes
	cfg.PkgRelationships = pkgRels
	return &cfg, nil
}

func (r *ConfigRepo) List() ([]*models.ScanConfig, error) {
	rows, err := r.db.Query(`
		SELECT id, name, description, target_type, target_pattern,
		       scanners, image_config_scanners, severity, ignore_unfixed,
		       detection_priority, pkg_types, pkg_relationships,
		       registry_auth, ignore_file, created_at, updated_at
		FROM scan_configs ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*models.ScanConfig
	for rows.Next() {
		var cfg models.ScanConfig
		var scanners, imageScanners, severity, pkgTypes, pkgRels []string
		err := rows.Scan(
			&cfg.ID, &cfg.Name, &cfg.Description, &cfg.TargetType, &cfg.TargetPattern,
			pq.Array(&scanners), pq.Array(&imageScanners), pq.Array(&severity),
			&cfg.IgnoreUnfixed, &cfg.DetectionPriority, pq.Array(&pkgTypes), pq.Array(&pkgRels),
			&cfg.RegistryAuth, &cfg.IgnoreFile, &cfg.CreatedAt, &cfg.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		cfg.Scanners = scanners
		cfg.ImageConfigScanners = imageScanners
		cfg.Severity = severity
		cfg.PkgTypes = pkgTypes
		cfg.PkgRelationships = pkgRels
		configs = append(configs, &cfg)
	}
	return configs, nil
}

func (r *ConfigRepo) Update(cfg *models.ScanConfig) error {
	_, err := r.db.Exec(`
		UPDATE scan_configs SET
			name = $1, description = $2, target_type = $3, target_pattern = $4,
			scanners = $5, image_config_scanners = $6, severity = $7,
			ignore_unfixed = $8, detection_priority = $9, pkg_types = $10,
			pkg_relationships = $11, registry_auth = $12, ignore_file = $13,
			updated_at = NOW()
		WHERE id = $14
	`,
		cfg.Name, cfg.Description, cfg.TargetType, cfg.TargetPattern,
		pq.Array(cfg.Scanners), pq.Array(cfg.ImageConfigScanners), pq.Array(cfg.Severity),
		cfg.IgnoreUnfixed, cfg.DetectionPriority, pq.Array(cfg.PkgTypes), pq.Array(cfg.PkgRelationships),
		cfg.RegistryAuth, cfg.IgnoreFile, cfg.ID,
	)
	return err
}

func (r *ConfigRepo) Delete(id int) error {
	_, err := r.db.Exec("DELETE FROM scan_configs WHERE id = $1", id)
	return err
}
