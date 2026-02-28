package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"trivy-scanner-ee/internal/db"
	"trivy-scanner-ee/internal/repo"
	"trivy-scanner-ee/internal/worker"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var scanRepo *repo.ScanRepo
var trivyServerURL string
var jobQueue chan int

func main() {
	log.Println("=== Starting Trivy Scanner Backend v2.1 (with vulnerabilities & packages API) ===")

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL not set")
	}
	trivyServerURL = os.Getenv("TRIVY_SERVER_URL")
	if trivyServerURL == "" {
		log.Fatal("TRIVY_SERVER_URL not set")
	}
	log.Printf("Database URL: %s", databaseURL)
	log.Printf("Trivy Server URL: %s", trivyServerURL)

	if err := db.Init(databaseURL); err != nil {
		log.Fatalf("DB init failed: %v", err)
	}
	log.Println("DB initialized successfully")

	scanRepo = repo.NewScanRepo(db.DB)
	if scanRepo == nil {
		log.Fatal("scanRepo is nil")
	}
	log.Println("ScanRepo created")

	jobQueue = make(chan int, 100)
	log.Println("Job queue created, starting worker...")
	go safeWorker(jobQueue, scanRepo, trivyServerURL)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Базовые маршруты
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Маршруты для сканов
	r.Post("/api/v1/scans", createScanHandler)
	r.Get("/api/v1/scans/{id}", getScanHandler)
	r.Get("/api/v1/scans/{id}/vulnerabilities", getVulnerabilitiesHandler)
	r.Get("/api/v1/scans/{id}/packages", getPackagesHandler)

	// Вывод зарегистрированных маршрутов
	log.Println("Registered routes:")
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		log.Printf("  %s %s", method, route)
		return nil
	}
	if err := chi.Walk(r, walkFunc); err != nil {
		log.Printf("Error walking routes: %v", err)
	}

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func safeWorker(jobQueue <-chan int, scanRepo *repo.ScanRepo, trivyServerURL string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Worker panicked: %v, restarting in 5s", r)
			time.Sleep(5 * time.Second)
			go safeWorker(jobQueue, scanRepo, trivyServerURL)
		}
	}()
	log.Println("Worker started")
	worker.StartWorker(jobQueue, scanRepo, trivyServerURL)
}

type createScanRequest struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

func createScanHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> createScanHandler called")

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
	id, err := scanRepo.CreateScan(req.Type, req.Target)
	if err != nil {
		log.Printf("ERROR: scanRepo.CreateScan failed: %v", err)
		http.Error(w, "Failed to create scan", http.StatusInternalServerError)
		return
	}
	log.Printf("Scan created with ID: %d", id)

	log.Printf("Sending ID %d to jobQueue", id)
	jobQueue <- id

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]int{"id": id})
	log.Println("Response sent with ID", id)
}

func getScanHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> getScanHandler called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("ERROR: invalid ID: %s", idStr)
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	log.Printf("Fetching scan ID: %d", id)

	scan, err := scanRepo.GetScan(id)
	if err != nil {
		log.Printf("ERROR: scan %d not found: %v", id, err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
	log.Printf("Scan %d retrieved", id)
}

// getVulnerabilitiesHandler возвращает список уязвимостей для скана
func getVulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> getVulnerabilitiesHandler called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("ERROR: invalid ID: %s", idStr)
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	log.Printf("Fetching vulnerabilities for scan ID: %d", id)

	vulns, err := scanRepo.GetVulnerabilities(id)
	if err != nil {
		log.Printf("ERROR: failed to get vulnerabilities for scan %d: %v", id, err)
		http.Error(w, "Failed to get vulnerabilities", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
	log.Printf("Returned %d vulnerabilities for scan %d", len(vulns), id)
}

// getPackagesHandler возвращает список пакетов для скана
func getPackagesHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> getPackagesHandler called")

	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("ERROR: invalid ID: %s", idStr)
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	log.Printf("Fetching packages for scan ID: %d", id)

	pkgs, err := scanRepo.GetPackages(id)
	if err != nil {
		log.Printf("ERROR: failed to get packages for scan %d: %v", id, err)
		http.Error(w, "Failed to get packages", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pkgs)
	log.Printf("Returned %d packages for scan %d", len(pkgs), id)
}
