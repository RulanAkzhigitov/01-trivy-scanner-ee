package repo

import (
	"database/sql"
	"trivy-scanner-ee/internal/models"

	"github.com/lib/pq"
)

type GroupRepo struct {
	db *sql.DB
}

func NewGroupRepo(db *sql.DB) *GroupRepo {
	return &GroupRepo{db: db}
}

func (r *GroupRepo) Create(group *models.ScanGroup) (int, error) {
	var id int
	err := r.db.QueryRow(`
		INSERT INTO scan_groups (
			name, description, config_ids, schedule, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		RETURNING id
	`, group.Name, group.Description, pq.Array(group.ConfigIDs), group.Schedule, group.IsActive).Scan(&id)
	return id, err
}

func (r *GroupRepo) GetByID(id int) (*models.ScanGroup, error) {
	var group models.ScanGroup
	var configIDs []int
	err := r.db.QueryRow(`
		SELECT id, name, description, config_ids, schedule, is_active, created_at, updated_at
		FROM scan_groups WHERE id = $1
	`, id).Scan(
		&group.ID, &group.Name, &group.Description, pq.Array(&configIDs),
		&group.Schedule, &group.IsActive, &group.CreatedAt, &group.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	group.ConfigIDs = configIDs
	return &group, nil
}

func (r *GroupRepo) List() ([]*models.ScanGroup, error) {
	rows, err := r.db.Query(`
		SELECT id, name, description, config_ids, schedule, is_active, created_at, updated_at
		FROM scan_groups ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*models.ScanGroup
	for rows.Next() {
		var group models.ScanGroup
		var configIDs []int
		err := rows.Scan(
			&group.ID, &group.Name, &group.Description, pq.Array(&configIDs),
			&group.Schedule, &group.IsActive, &group.CreatedAt, &group.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		group.ConfigIDs = configIDs
		groups = append(groups, &group)
	}
	return groups, nil
}

func (r *GroupRepo) Update(group *models.ScanGroup) error {
	_, err := r.db.Exec(`
		UPDATE scan_groups SET
			name = $1, description = $2, config_ids = $3,
			schedule = $4, is_active = $5, updated_at = NOW()
		WHERE id = $6
	`, group.Name, group.Description, pq.Array(group.ConfigIDs),
		group.Schedule, group.IsActive, group.ID)
	return err
}

func (r *GroupRepo) Delete(id int) error {
	_, err := r.db.Exec("DELETE FROM scan_groups WHERE id = $1", id)
	return err
}

// GetActiveGroups возвращает все активные группы для планировщика
func (r *GroupRepo) GetActiveGroups() ([]*models.ScanGroup, error) {
	rows, err := r.db.Query(`
		SELECT id, name, description, config_ids, schedule, is_active, created_at, updated_at
		FROM scan_groups
		WHERE is_active = true AND schedule != ''
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*models.ScanGroup
	for rows.Next() {
		var group models.ScanGroup
		var configIDs []int
		err := rows.Scan(
			&group.ID, &group.Name, &group.Description, pq.Array(&configIDs),
			&group.Schedule, &group.IsActive, &group.CreatedAt, &group.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		group.ConfigIDs = configIDs
		groups = append(groups, &group)
	}
	return groups, nil
}
