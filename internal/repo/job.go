package repo

import (
	"database/sql"
	"time"
	"trivy-scanner-ee/internal/models"
)

type JobRepo struct {
	db *sql.DB
}

func NewJobRepo(db *sql.DB) *JobRepo {
	return &JobRepo{db: db}
}

func (r *JobRepo) Create(job *models.ScanJob) (int, error) {
	var id int
	err := r.db.QueryRow(`
		INSERT INTO scan_jobs (
			config_id, name, status, target, parameters, pid,
			started_at, finished_at, error, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		RETURNING id
	`,
		job.ConfigID, job.Name, job.Status, job.Target, job.Parameters,
		job.PID, job.StartedAt, job.FinishedAt, job.Error,
	).Scan(&id)
	return id, err
}

func (r *JobRepo) GetByID(id int) (*models.ScanJob, error) {
	var job models.ScanJob
	err := r.db.QueryRow(`
		SELECT id, config_id, name, status, target, parameters, pid,
		       started_at, finished_at, error, created_at
		FROM scan_jobs WHERE id = $1
	`, id).Scan(
		&job.ID, &job.ConfigID, &job.Name, &job.Status, &job.Target, &job.Parameters,
		&job.PID, &job.StartedAt, &job.FinishedAt, &job.Error, &job.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (r *JobRepo) ListByConfig(configID int, limit, offset int) ([]*models.ScanJob, error) {
	rows, err := r.db.Query(`
		SELECT id, config_id, name, status, target, parameters, pid,
		       started_at, finished_at, error, created_at
		FROM scan_jobs
		WHERE config_id = $1
		ORDER BY id DESC
		LIMIT $2 OFFSET $3
	`, configID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*models.ScanJob
	for rows.Next() {
		var job models.ScanJob
		err := rows.Scan(
			&job.ID, &job.ConfigID, &job.Name, &job.Status, &job.Target, &job.Parameters,
			&job.PID, &job.StartedAt, &job.FinishedAt, &job.Error, &job.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, &job)
	}
	return jobs, nil
}

func (r *JobRepo) ListAll(limit, offset int) ([]*models.ScanJob, error) {
	rows, err := r.db.Query(`
		SELECT id, config_id, name, status, target, parameters, pid,
		       started_at, finished_at, error, created_at
		FROM scan_jobs
		ORDER BY id DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*models.ScanJob
	for rows.Next() {
		var job models.ScanJob
		err := rows.Scan(
			&job.ID, &job.ConfigID, &job.Name, &job.Status, &job.Target, &job.Parameters,
			&job.PID, &job.StartedAt, &job.FinishedAt, &job.Error, &job.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, &job)
	}
	return jobs, nil
}

func (r *JobRepo) UpdateStatus(jobID int, status string, pid int, startedAt, finishedAt *time.Time, errMsg string) error {
	_, err := r.db.Exec(`
		UPDATE scan_jobs
		SET status = $1, pid = $2, started_at = $3, finished_at = $4, error = $5
		WHERE id = $6
	`, status, pid, startedAt, finishedAt, errMsg, jobID)
	return err
}

func (r *JobRepo) SaveResult(result *models.ScanResult) error {
	_, err := r.db.Exec(`
		INSERT INTO scan_results (job_id, result_type, target, class, data)
		VALUES ($1, $2, $3, $4, $5)
	`, result.JobID, result.ResultType, result.Target, result.Class, result.Data)
	return err
}

func (r *JobRepo) GetResults(jobID int) ([]*models.ScanResult, error) {
	rows, err := r.db.Query(`
		SELECT id, job_id, result_type, target, class, data
		FROM scan_results
		WHERE job_id = $1
		ORDER BY id
	`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.ScanResult
	for rows.Next() {
		var res models.ScanResult
		err := rows.Scan(&res.ID, &res.JobID, &res.ResultType, &res.Target, &res.Class, &res.Data)
		if err != nil {
			return nil, err
		}
		results = append(results, &res)
	}
	return results, nil
}

func (r *JobRepo) Delete(jobID int) error {
	_, err := r.db.Exec("DELETE FROM scan_jobs WHERE id = $1", jobID)
	return err
}
