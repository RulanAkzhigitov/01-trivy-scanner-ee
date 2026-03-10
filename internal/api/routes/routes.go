package routes

import (
	"trivy-scanner-ee/internal/api/handlers"

	"github.com/go-chi/chi/v5"
)

type HandlerDeps struct {
	ScanHandlers    *handlers.ScanHandlers
	ConfigHandlers  *handlers.ConfigHandlers
	JobHandlers     *handlers.JobHandlers
	GroupHandlers   *handlers.GroupHandlers
	WebhookHandlers *handlers.WebhookHandlers
	QuickHandlers   *handlers.QuickHandlers // добавляем
}

func SetupRoutes(deps *HandlerDeps) chi.Router {
	r := chi.NewRouter()

	// Старые сканы (пока оставляем для обратной совместимости)
	r.Post("/scans", deps.ScanHandlers.CreateScan)
	r.Get("/scans/{id}", deps.ScanHandlers.GetScan)
	r.Get("/scans/{id}/vulnerabilities", deps.ScanHandlers.GetVulnerabilities)
	r.Get("/scans/{id}/packages", deps.ScanHandlers.GetPackages)

	// НОВЫЙ: быстрый скан через задания
	r.Post("/quick-scan", deps.QuickHandlers.QuickScan)

	// Конфигурации
	r.Route("/configs", func(r chi.Router) {
		r.Post("/", deps.ConfigHandlers.CreateConfig)
		r.Get("/", deps.ConfigHandlers.ListConfigs)
		r.Get("/{id}", deps.ConfigHandlers.GetConfig)
		r.Put("/{id}", deps.ConfigHandlers.UpdateConfig)
		r.Delete("/{id}", deps.ConfigHandlers.DeleteConfig)
		r.Post("/{id}/run", deps.ConfigHandlers.RunConfig)
	})

	// Задания
	r.Route("/jobs", func(r chi.Router) {
		r.Get("/", deps.JobHandlers.ListJobs)
		r.Get("/{id}", deps.JobHandlers.GetJob)
		r.Post("/{id}/stop", deps.JobHandlers.StopJob)
		r.Delete("/{id}", deps.JobHandlers.DeleteJob)
	})

	// Группы
	r.Route("/groups", func(r chi.Router) {
		r.Post("/", deps.GroupHandlers.CreateGroup)
		r.Get("/", deps.GroupHandlers.ListGroups)
		r.Get("/{id}", deps.GroupHandlers.GetGroup)
		r.Put("/{id}", deps.GroupHandlers.UpdateGroup)
		r.Delete("/{id}", deps.GroupHandlers.DeleteGroup)
		r.Post("/{id}/run", deps.GroupHandlers.RunGroup)
	})

	// Вебхуки
	r.Post("/webhooks/harbor", deps.WebhookHandlers.HarborWebhook)

	return r
}
