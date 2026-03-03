package worker

import (
	"encoding/json"
	"log"
	"os/exec"
	"time"

	"trivy-scanner-ee/internal/models"
	"trivy-scanner-ee/internal/repo"
)

type scanWorker struct {
	scanRepo       *repo.ScanRepo
	trivyServerURL string
}

func StartScanWorker(scanQueue <-chan int, scanRepo *repo.ScanRepo, trivyServerURL string) {
	w := &scanWorker{
		scanRepo:       scanRepo,
		trivyServerURL: trivyServerURL,
	}
	for scanID := range scanQueue {
		log.Printf("Scan worker picked scan ID: %d", scanID)
		w.runScan(scanID)
	}
}

func (w *scanWorker) runScan(scanID int) {
	scan, err := w.scanRepo.GetScan(scanID)
	if err != nil {
		log.Printf("Failed to get scan %d: %v", scanID, err)
		return
	}

	now := time.Now()
	w.scanRepo.UpdateScanStatus(scanID, "running", &now, nil, "")

	cmd := exec.Command("trivy", "image",
		"--server", w.trivyServerURL,
		scan.Target,
		"--format", "json",
		"--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
	)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("Trivy error: %s", exitErr.Stderr)
		}
		w.scanRepo.UpdateScanStatus(scanID, "failed", nil, nil, err.Error())
		return
	}

	var result struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Description      string `json:"Description"`
			} `json:"Vulnerabilities"`
			Packages []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Arch    string `json:"arch"`
			} `json:"Packages"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		log.Printf("Failed to parse Trivy output: %v", err)
		w.scanRepo.UpdateScanStatus(scanID, "failed", nil, nil, err.Error())
		return
	}

	for _, res := range result.Results {
		// Пакеты
		pkgs := make([]models.Package, 0, len(res.Packages))
		for _, p := range res.Packages {
			pkgs = append(pkgs, models.Package{
				ScanID:  scanID,
				Name:    p.Name,
				Version: p.Version,
				Arch:    p.Arch,
			})
		}
		if err := w.scanRepo.SavePackages(scanID, pkgs); err != nil {
			log.Printf("Failed to save packages: %v", err)
		}

		// Уязвимости
		vulns := make([]models.Vulnerability, 0, len(res.Vulnerabilities))
		for _, v := range res.Vulnerabilities {
			vulns = append(vulns, models.Vulnerability{
				ScanID:           scanID,
				VulnerabilityID:  v.VulnerabilityID,
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         v.Severity,
				Description:      v.Description,
			})
		}
		if err := w.scanRepo.SaveVulnerabilities(scanID, vulns); err != nil {
			log.Printf("Failed to save vulnerabilities: %v", err)
		}
	}

	finished := time.Now()
	w.scanRepo.UpdateScanStatus(scanID, "completed", nil, &finished, "")
	log.Printf("Scan %d completed", scanID)
}
