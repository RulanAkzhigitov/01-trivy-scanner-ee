package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"

	"trivy-scanner-ee/internal/models"
	"trivy-scanner-ee/internal/repo"
)

type WebhookHandlers struct {
	configRepo *repo.ConfigRepo
	jobRepo    *repo.JobRepo
	jobQueue   chan<- int
}

func NewWebhookHandlers(configRepo *repo.ConfigRepo, jobRepo *repo.JobRepo, jobQueue chan<- int) *WebhookHandlers {
	return &WebhookHandlers{
		configRepo: configRepo,
		jobRepo:    jobRepo,
		jobQueue:   jobQueue,
	}
}

func (h *WebhookHandlers) HarborWebhook(w http.ResponseWriter, r *http.Request) {
	log.Println(">>> HarborWebhook called")

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("ERROR: failed to decode harbor webhook: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	eventType, ok := payload["type"].(string)
	if !ok {
		log.Println("WARN: missing event type, ignoring")
		w.WriteHeader(http.StatusOK)
		return
	}

	if eventType != "PUSH_ARTIFACT" {
		log.Printf("Ignoring event type: %s", eventType)
		w.WriteHeader(http.StatusOK)
		return
	}

	eventData, ok := payload["event_data"].(map[string]interface{})
	if !ok {
		log.Println("ERROR: event_data missing")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	resources, ok := eventData["resources"].([]interface{})
	if !ok || len(resources) == 0 {
		log.Println("ERROR: no resources in event_data")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	resource, ok := resources[0].(map[string]interface{})
	if !ok {
		log.Println("ERROR: resource is not an object")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	resourceURL, ok := resource["resource_url"].(string)
	if !ok || resourceURL == "" {
		log.Println("ERROR: resource_url missing or empty")
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	log.Printf("Harbor webhook received for resource: %s", resourceURL)

	configs, err := h.configRepo.List()
	if err != nil {
		log.Printf("ERROR: failed to list configs: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	jobsCreated := 0
	for _, cfg := range configs {
		matched, err := path.Match(cfg.TargetPattern, resourceURL)
		if err != nil {
			log.Printf("WARN: pattern error for %s: %v", cfg.TargetPattern, err)
			continue
		}
		if matched {
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
				Name:       fmt.Sprintf("Webhook: %s", resourceURL),
				Status:     "pending",
				Target:     resourceURL,
				Parameters: params,
			}
			jobID, err := h.jobRepo.Create(job)
			if err != nil {
				log.Printf("ERROR: failed to create job for config %d: %v", cfg.ID, err)
				continue
			}
			h.jobQueue <- jobID
			jobsCreated++
			log.Printf("Created job %d for config %d (target: %s)", jobID, cfg.ID, resourceURL)
		}
	}

	if jobsCreated == 0 {
		log.Printf("No matching configs for resource %s", resourceURL)
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]int{"jobs_created": jobsCreated})
}
