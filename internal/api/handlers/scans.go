package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"trivy-scanner-ee/internal/repo"

	"github.com/go-chi/chi/v5"
)

type ScanHandlers struct {
	scanRepo  *repo.ScanRepo
	scanQueue chan<- int
}

func NewScanHandlers(scanRepo *repo.ScanRepo, scanQueue chan<- int) *ScanHandlers {
	return &ScanHandlers{
		scanRepo:  scanRepo,
		scanQueue: scanQueue,
	}
}

type createScanRequest struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

func (h *ScanHandlers) CreateScan(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> CreateScan called")

	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("ERROR: invalid JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	log.Printf("Request: type=%s target=%s", req.Type, req.Target)

	if req.Type != "image" {
		log.Printf("ERROR: unsupported type %s", req.Type)
		http.Error(w, "Only 'image' type supported now", http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		log.Printf("ERROR: empty target")
		http.Error(w, "Target required", http.StatusBadRequest)
		return
	}

	log.Println("Calling scanRepo.CreateScan...")
	id, err := h.scanRepo.CreateScan(req.Type, req.Target)
	if err != nil {
		log.Printf("ERROR: scanRepo.CreateScan failed: %v", err)
		http.Error(w, "Failed to create scan", http.StatusInternalServerError)
		return
	}
	log.Printf("Scan created with ID: %d", id)

	log.Printf("Sending ID %d to scanQueue", id)
	h.scanQueue <- id

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]int{"id": id})
	log.Println("Response sent with ID", id)
}

func (h *ScanHandlers) GetScan(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> GetScan called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("ERROR: invalid ID: %s", idStr)
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	log.Printf("Fetching scan ID: %d", id)

	scan, err := h.scanRepo.GetScan(id)
	if err != nil {
		log.Printf("ERROR: scan %d not found: %v", id, err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
	log.Printf("Scan %d retrieved", id)
}

func (h *ScanHandlers) GetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> GetVulnerabilities called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("ERROR: invalid ID: %s", idStr)
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	log.Printf("Fetching vulnerabilities for scan ID: %d", id)

	vulns, err := h.scanRepo.GetVulnerabilities(id)
	if err != nil {
		log.Printf("ERROR: failed to get vulnerabilities: %v", err)
		http.Error(w, "Failed to get vulnerabilities", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
	log.Printf("Returned %d vulnerabilities", len(vulns))
}

func (h *ScanHandlers) GetPackages(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> GetPackages called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("ERROR: invalid ID: %s", idStr)
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	log.Printf("Fetching packages for scan ID: %d", id)

	pkgs, err := h.scanRepo.GetPackages(id)
	if err != nil {
		log.Printf("ERROR: failed to get packages: %v", err)
		http.Error(w, "Failed to get packages", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pkgs)
	log.Printf("Returned %d packages", len(pkgs))
}
