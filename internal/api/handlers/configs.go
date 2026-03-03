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

type ConfigHandlers struct {
	configRepo *repo.ConfigRepo
	jobRepo    *repo.JobRepo
	jobQueue   chan<- int
}

func NewConfigHandlers(configRepo *repo.ConfigRepo, jobRepo *repo.JobRepo, jobQueue chan<- int) *ConfigHandlers {
	return &ConfigHandlers{
		configRepo: configRepo,
		jobRepo:    jobRepo,
		jobQueue:   jobQueue,
	}
}

type createConfigRequest struct {
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	TargetType          string                 `json:"target_type"`
	TargetPattern       string                 `json:"target_pattern"`
	Scanners            []string               `json:"scanners"`
	ImageConfigScanners []string               `json:"image_config_scanners"`
	Severity            []string               `json:"severity"`
	IgnoreUnfixed       bool                   `json:"ignore_unfixed"`
	DetectionPriority   string                 `json:"detection_priority"`
	PkgTypes            []string               `json:"pkg_types"`
	PkgRelationships    []string               `json:"pkg_relationships"`
	RegistryAuth        map[string]interface{} `json:"registry_auth,omitempty"`
	IgnoreFile          string                 `json:"ignore_file,omitempty"`
}

func (h *ConfigHandlers) CreateConfig(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> CreateConfig called")

	var req createConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("ERROR: invalid JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Валидация
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.TargetType == "" {
		req.TargetType = "image"
	}
	if req.TargetPattern == "" {
		http.Error(w, "target_pattern is required", http.StatusBadRequest)
		return
	}
	if len(req.Scanners) == 0 {
		req.Scanners = []string{"vuln", "secret"}
	}
	if len(req.Severity) == 0 {
		req.Severity = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	}
	if req.DetectionPriority == "" {
		req.DetectionPriority = "precise"
	}
	if len(req.PkgTypes) == 0 {
		req.PkgTypes = []string{"os", "library"}
	}
	if len(req.PkgRelationships) == 0 {
		req.PkgRelationships = []string{"root", "direct", "indirect", "unknown"}
	}

	cfg := &models.ScanConfig{
		Name:                req.Name,
		Description:         req.Description,
		TargetType:          req.TargetType,
		TargetPattern:       req.TargetPattern,
		Scanners:            req.Scanners,
		ImageConfigScanners: req.ImageConfigScanners,
		Severity:            req.Severity,
		IgnoreUnfixed:       req.IgnoreUnfixed,
		DetectionPriority:   req.DetectionPriority,
		PkgTypes:            req.PkgTypes,
		PkgRelationships:    req.PkgRelationships,
		RegistryAuth:        req.RegistryAuth,
		IgnoreFile:          req.IgnoreFile,
	}

	id, err := h.configRepo.Create(cfg)
	if err != nil {
		log.Printf("ERROR: failed to create config: %v", err)
		http.Error(w, "Failed to create config", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]int{"id": id})
}

func (h *ConfigHandlers) ListConfigs(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> ListConfigs called")

	configs, err := h.configRepo.List()
	if err != nil {
		log.Printf("ERROR: failed to list configs: %v", err)
		http.Error(w, "Failed to list configs", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configs)
}

func (h *ConfigHandlers) GetConfig(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> GetConfig called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	cfg, err := h.configRepo.GetByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Config not found", http.StatusNotFound)
		} else {
			log.Printf("ERROR: failed to get config %d: %v", id, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (h *ConfigHandlers) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> UpdateConfig called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	var req createConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("ERROR: invalid JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	existing, err := h.configRepo.GetByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Config not found", http.StatusNotFound)
		} else {
			log.Printf("ERROR: failed to get config %d: %v", id, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	// Обновляем поля
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.TargetType != "" {
		existing.TargetType = req.TargetType
	}
	if req.TargetPattern != "" {
		existing.TargetPattern = req.TargetPattern
	}
	if len(req.Scanners) > 0 {
		existing.Scanners = req.Scanners
	}
	if len(req.ImageConfigScanners) > 0 {
		existing.ImageConfigScanners = req.ImageConfigScanners
	}
	if len(req.Severity) > 0 {
		existing.Severity = req.Severity
	}
	existing.IgnoreUnfixed = req.IgnoreUnfixed
	if req.DetectionPriority != "" {
		existing.DetectionPriority = req.DetectionPriority
	}
	if len(req.PkgTypes) > 0 {
		existing.PkgTypes = req.PkgTypes
	}
	if len(req.PkgRelationships) > 0 {
		existing.PkgRelationships = req.PkgRelationships
	}
	if req.RegistryAuth != nil {
		existing.RegistryAuth = req.RegistryAuth
	}
	if req.IgnoreFile != "" {
		existing.IgnoreFile = req.IgnoreFile
	}

	if err := h.configRepo.Update(existing); err != nil {
		log.Printf("ERROR: failed to update config %d: %v", id, err)
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func (h *ConfigHandlers) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> DeleteConfig called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := h.configRepo.Delete(id); err != nil {
		log.Printf("ERROR: failed to delete config %d: %v", id, err)
		http.Error(w, "Failed to delete config", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ConfigHandlers) RunConfig(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> RunConfig called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	cfg, err := h.configRepo.GetByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Config not found", http.StatusNotFound)
		} else {
			log.Printf("ERROR: failed to get config %d: %v", id, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
		return
	}

	// TODO: поддержка паттернов
	target := cfg.TargetPattern

	params := map[string]interface{}{
		"scanners":              cfg.Scanners,
		"image_config_scanners": cfg.ImageConfigScanners,
		"severity":              cfg.Severity,
		"ignore_unfixed":        cfg.IgnoreUnfixed,
		"detection_priority":    cfg.DetectionPriority,
		"pkg_types":             cfg.PkgTypes,
		"pkg_relationships":     cfg.PkgRelationships,
	}

	job := &models.ScanJob{
		ConfigID:   &cfg.ID,
		Name:       cfg.Name,
		Status:     "pending",
		Target:     target,
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
	json.NewEncoder(w).Encode(map[string]int{"job_id": jobID})
}
