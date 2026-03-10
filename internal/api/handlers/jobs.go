package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"trivy-scanner-ee/internal/models"
	"trivy-scanner-ee/internal/repo"

	"github.com/go-chi/chi/v5"
)

type JobHandlers struct {
	jobRepo *repo.JobRepo
}

func NewJobHandlers(jobRepo *repo.JobRepo) *JobHandlers {
	return &JobHandlers{
		jobRepo: jobRepo,
	}
}

func (h *JobHandlers) ListJobs(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> ListJobs called")

	limit := 20
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	if configIDStr := r.URL.Query().Get("config_id"); configIDStr != "" {
		configID, err := strconv.Atoi(configIDStr)
		if err != nil {
			http.Error(w, "Invalid config_id", http.StatusBadRequest)
			return
		}
		jobs, err := h.jobRepo.ListByConfig(configID, limit, offset)
		if err != nil {
			log.Printf("ERROR: failed to list jobs: %v", err)
			http.Error(w, "Failed to list jobs", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jobs)
		return
	}

	jobs, err := h.jobRepo.ListAll(limit, offset)
	if err != nil {
		log.Printf("ERROR: failed to list jobs: %v", err)
		http.Error(w, "Failed to list jobs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

func (h *JobHandlers) GetJob(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> GetJob called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	job, err := h.jobRepo.GetByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Job not found", http.StatusNotFound)
		} else {
			log.Printf("ERROR: failed to get job %d: %v", id, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	results, _ := h.jobRepo.GetResults(id)
	response := struct {
		*models.ScanJob
		Results []*models.ScanResult `json:"results,omitempty"`
	}{
		ScanJob: job,
		Results: results,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *JobHandlers) StopJob(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> StopJob called (not implemented)")
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (h *JobHandlers) DeleteJob(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> DeleteJob called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := h.jobRepo.Delete(id); err != nil {
		log.Printf("ERROR: failed to delete job %d: %v", id, err)
		http.Error(w, "Failed to delete job", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
