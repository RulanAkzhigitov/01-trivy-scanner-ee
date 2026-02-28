package worker

import (
    "encoding/json"
    "log"
    "os/exec"
    "time"
    "trivy-scanner-ee/internal/models"
    "trivy-scanner-ee/internal/repo"
)

type trivyOutput struct {
    ArtifactName string `json:"ArtifactName"`
    Results      []struct {
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

func StartWorker(jobQueue <-chan int, scanRepo *repo.ScanRepo, trivyServerURL string) {
    for scanID := range jobQueue {
        log.Printf("Worker picked scan ID: %d", scanID)
        runScan(scanID, scanRepo, trivyServerURL)
    }
}

func runScan(scanID int, scanRepo *repo.ScanRepo, trivyServerURL string) {
    scan, err := scanRepo.GetScan(scanID)
    if err != nil {
        log.Printf("Failed to get scan %d: %v", scanID, err)
        return
    }

    now := time.Now()
    scanRepo.UpdateScanStatus(scanID, "running", &now, nil, "")

    // Запускаем Trivy (предполагается, что бинарник trivy доступен в PATH)
    cmd := exec.Command("trivy", "image",
        "--server", trivyServerURL,
        scan.Target,
        "--format", "json",
        "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    )
    output, err := cmd.Output()
    if err != nil {
        if exitErr, ok := err.(*exec.ExitError); ok {
            log.Printf("Trivy error: %s", exitErr.Stderr)
        }
        scanRepo.UpdateScanStatus(scanID, "failed", nil, nil, err.Error())
        return
    }

    var result trivyOutput
    if err := json.Unmarshal(output, &result); err != nil {
        log.Printf("Failed to parse Trivy output: %v", err)
        scanRepo.UpdateScanStatus(scanID, "failed", nil, nil, err.Error())
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
        if err := scanRepo.SavePackages(scanID, pkgs); err != nil {
            log.Printf("Failed to save packages: %v", err)
        }

        // Уязвимости
        vulns := make([]models.Vulnerability, 0, len(res.Vulnerabilities))
        for _, v := range res.Vulnerabilities {
            vulns = append(vulns, models.Vulnerability{
                ScanID:          scanID,
                VulnerabilityID: v.VulnerabilityID,
                Package:         v.PkgName,
                InstalledVersion: v.InstalledVersion,
                FixedVersion:    v.FixedVersion,
                Severity:        v.Severity,
                Description:     v.Description,
            })
        }
        if err := scanRepo.SaveVulnerabilities(scanID, vulns); err != nil {
            log.Printf("Failed to save vulnerabilities: %v", err)
        }
    }

    finished := time.Now()
    scanRepo.UpdateScanStatus(scanID, "completed", nil, &finished, "")
    log.Printf("Scan %d completed", scanID)
}