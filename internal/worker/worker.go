package worker

import (
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"time"

	"trivy-scanner-ee/internal/models"
	"trivy-scanner-ee/internal/repo"
)

// StartWorker запускает воркер, обрабатывающий задания из канала
func StartWorker(jobQueue <-chan int, jobRepo *repo.JobRepo, trivyServerURL string) {
	for jobID := range jobQueue {
		log.Printf("Worker picked job ID: %d", jobID)
		runJob(jobID, jobRepo, trivyServerURL)
	}
}

// runJob выполняет одно задание
func runJob(jobID int, jobRepo *repo.JobRepo, trivyServerURL string) {
	// Загружаем задание из БД
	job, err := jobRepo.GetByID(jobID)
	if err != nil {
		log.Printf("Failed to get job %d: %v", jobID, err)
		return
	}

	// Обновляем статус на running
	now := time.Now()
	jobRepo.UpdateStatus(jobID, "running", 0, &now, nil, "")

	// Формируем команду Trivy из параметров
	args := buildTrivyArgs(job.Parameters, trivyServerURL, job.Target)
	log.Printf("Running trivy with args: %v", args)

	cmd := exec.Command("trivy", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("Trivy error (stderr): %s", exitErr.Stderr)
		}
		jobRepo.UpdateStatus(jobID, "failed", 0, nil, &now, err.Error())
		return
	}

	// Парсим JSON
	var trivyReport map[string]interface{}
	if err := json.Unmarshal(output, &trivyReport); err != nil {
		log.Printf("Failed to parse Trivy output: %v", err)
		jobRepo.UpdateStatus(jobID, "failed", 0, nil, &now, err.Error())
		return
	}

	// Извлекаем Results и сохраняем каждый как отдельный результат
	if results, ok := trivyReport["Results"].([]interface{}); ok {
		for _, res := range results {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}

			// Определяем тип результата
			var resultType string
			switch {
			case hasKey(resMap, "Vulnerabilities"):
				resultType = "vuln"
			case hasKey(resMap, "Misconfigurations"):
				resultType = "misconfig"
			case hasKey(resMap, "Secrets"):
				resultType = "secret"
			case hasKey(resMap, "Licenses"):
				resultType = "license"
			default:
				continue
			}

			target, _ := resMap["Target"].(string)
			class, _ := resMap["Class"].(string)

			// Сохраняем в БД
			scanResult := &models.ScanResult{
				JobID:      jobID,
				ResultType: resultType,
				Target:     target,
				Class:      class,
				Data:       resMap,
			}
			if err := jobRepo.SaveResult(scanResult); err != nil {
				log.Printf("Failed to save result for job %d: %v", jobID, err)
			}
		}
	}

	// Завершаем успешно
	finished := time.Now()
	jobRepo.UpdateStatus(jobID, "completed", 0, nil, &finished, "")
	log.Printf("Job %d completed", jobID)
}

// buildTrivyArgs формирует аргументы командной строки для trivy из параметров
func buildTrivyArgs(params map[string]interface{}, serverURL, target string) []string {
	args := []string{"image", "--server", serverURL, "--format", "json"}

	// Сканеры
	if scanners, ok := params["scanners"].([]interface{}); ok {
		scannerList := make([]string, len(scanners))
		for i, s := range scanners {
			scannerList[i] = s.(string)
		}
		args = append(args, "--scanners", strings.Join(scannerList, ","))
	}

	// Сканеры для конфигурации образа
	if imgScanners, ok := params["image_config_scanners"].([]interface{}); ok && len(imgScanners) > 0 {
		scannerList := make([]string, len(imgScanners))
		for i, s := range imgScanners {
			scannerList[i] = s.(string)
		}
		args = append(args, "--image-config-scanners", strings.Join(scannerList, ","))
	}

	// Уровни severity
	if severity, ok := params["severity"].([]interface{}); ok {
		sevList := make([]string, len(severity))
		for i, s := range severity {
			sevList[i] = s.(string)
		}
		args = append(args, "--severity", strings.Join(sevList, ","))
	}

	// Игнорировать unfixed
	if ignoreUnfixed, ok := params["ignore_unfixed"].(bool); ok && ignoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}

	// Приоритет обнаружения
	if priority, ok := params["detection_priority"].(string); ok && priority != "" {
		args = append(args, "--detection-priority", priority)
	}

	// Типы пакетов
	if pkgTypes, ok := params["pkg_types"].([]interface{}); ok {
		types := make([]string, len(pkgTypes))
		for i, t := range pkgTypes {
			types[i] = t.(string)
		}
		args = append(args, "--pkg-types", strings.Join(types, ","))
	}

	// Отношения пакетов
	if pkgRels, ok := params["pkg_relationships"].([]interface{}); ok {
		rels := make([]string, len(pkgRels))
		for i, r := range pkgRels {
			rels[i] = r.(string)
		}
		args = append(args, "--pkg-relationships", strings.Join(rels, ","))
	}

	args = append(args, target)
	return args
}

// hasKey проверяет наличие ключа в map
func hasKey(m map[string]interface{}, key string) bool {
	_, ok := m[key]
	return ok
}
