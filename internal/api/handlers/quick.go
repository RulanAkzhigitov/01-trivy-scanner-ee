package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"trivy-scanner-ee/internal/models"
	"trivy-scanner-ee/internal/repo"
)

type QuickHandlers struct {
	jobRepo  *repo.JobRepo
	jobQueue chan<- int
}

func NewQuickHandlers(jobRepo *repo.JobRepo, jobQueue chan<- int) *QuickHandlers {
	return &QuickHandlers{
		jobRepo:  jobRepo,
		jobQueue: jobQueue,
	}
}

type quickScanRequest struct {
	Target string `json:"target"`
}

func (h *QuickHandlers) QuickScan(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> QuickScan called")

	var req quickScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("ERROR: invalid JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		log.Printf("ERROR: empty target")
		http.Error(w, "Target required", http.StatusBadRequest)
		return
	}

	// Параметры по умолчанию
	params := map[string]interface{}{
		"scanners":           []string{"vuln", "secret"},
		"severity":           []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
		"ignore_unfixed":     false,
		"detection_priority": "precise",
		"pkg_types":          []string{"os", "library"},
		"pkg_relationships":  []string{"root", "direct", "indirect", "unknown"},
	}

	job := &models.ScanJob{
		ConfigID:   nil, // NULL для заданий без конфигурации
		Name:       "Quick scan: " + req.Target,
		Status:     "pending",
		Target:     req.Target,
		Parameters: params,
	}

	jobID, err := h.jobRepo.Create(job)
	if err != nil {
		log.Printf("ERROR: failed to create job: %v", err)
		http.Error(w, "Failed to create job", http.StatusInternalServerError)
		return
	}

	h.jobQueue <- jobID

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]int{"id": jobID})
	log.Printf("Quick scan job created with ID: %d", jobID)
}
