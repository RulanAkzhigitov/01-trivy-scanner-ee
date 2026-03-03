package worker

import (
	"encoding/json"
	"log"
	"os/exec"
	"time"

	"trivy-scanner-ee/internal/models"
	"trivy-scanner-ee/internal/repo"
	"trivy-scanner-ee/internal/trivy"
)

type jobWorker struct {
	jobRepo        *repo.JobRepo
	trivyServerURL string
}

func StartJobWorker(jobQueue <-chan int, jobRepo *repo.JobRepo, trivyServerURL string) {
	w := &jobWorker{
		jobRepo:        jobRepo,
		trivyServerURL: trivyServerURL,
	}
	for jobID := range jobQueue {
		log.Printf("Job worker picked job ID: %d", jobID)
		w.runJob(jobID)
	}
}

func (w *jobWorker) runJob(jobID int) {
	job, err := w.jobRepo.GetByID(jobID)
	if err != nil {
		log.Printf("Failed to get job %d: %v", jobID, err)
		return
	}

	now := time.Now()
	w.jobRepo.UpdateStatus(jobID, "running", 0, &now, nil, "")

	args := trivy.BuildTrivyArgs(job.Parameters, w.trivyServerURL, job.Target)
	log.Printf("Running trivy with args: %v", args)

	cmd := exec.Command("trivy", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("Trivy error (stderr): %s", exitErr.Stderr)
		}
		w.jobRepo.UpdateStatus(jobID, "failed", 0, nil, &now, err.Error())
		return
	}

	var trivyReport map[string]interface{}
	if err := json.Unmarshal(output, &trivyReport); err != nil {
		log.Printf("Failed to parse Trivy output: %v", err)
		w.jobRepo.UpdateStatus(jobID, "failed", 0, nil, &now, err.Error())
		return
	}

	if results, ok := trivyReport["Results"].([]interface{}); ok {
		for _, res := range results {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			var resultType string
			switch {
			case trivy.HasKey(resMap, "Vulnerabilities"):
				resultType = "vuln"
			case trivy.HasKey(resMap, "Misconfigurations"):
				resultType = "misconfig"
			case trivy.HasKey(resMap, "Secrets"):
				resultType = "secret"
			case trivy.HasKey(resMap, "Licenses"):
				resultType = "license"
			default:
				continue
			}

			target, _ := resMap["Target"].(string)
			class, _ := resMap["Class"].(string)

			scanResult := &models.ScanResult{
				JobID:      jobID,
				ResultType: resultType,
				Target:     target,
				Class:      class,
				Data:       resMap,
			}
			if err := w.jobRepo.SaveResult(scanResult); err != nil {
				log.Printf("Failed to save result for job %d: %v", jobID, err)
			}
		}
	}

	finished := time.Now()
	w.jobRepo.UpdateStatus(jobID, "completed", 0, nil, &finished, "")
	log.Printf("Job %d completed", jobID)
}
