package main

import (
	"log"
	"net/http"
	"os"

	"trivy-scanner-ee/internal/api/handlers"
	"trivy-scanner-ee/internal/api/routes"
	"trivy-scanner-ee/internal/db"
	"trivy-scanner-ee/internal/repo"
	"trivy-scanner-ee/internal/worker"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func main() {
	log.Println("=== Starting Trivy Scanner Backend v3.3 (with unified quick scan) ===")

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL not set")
	}
	trivyServerURL := os.Getenv("TRIVY_SERVER_URL")
	if trivyServerURL == "" {
		log.Fatal("TRIVY_SERVER_URL not set")
	}

	if err := db.Init(databaseURL); err != nil {
		log.Fatalf("DB init failed: %v", err)
	}
	log.Println("DB initialized successfully")

	// Репозитории
	scanRepo := repo.NewScanRepo(db.DB)
	configRepo := repo.NewConfigRepo(db.DB)
	jobRepo := repo.NewJobRepo(db.DB)
	// groupRepo := repo.NewGroupRepo(db.DB) // пока не используется

	// Два отдельных канала
	scanQueue := make(chan int, 100)
	jobQueue := make(chan int, 100)

	// Воркеры
	go worker.StartScanWorker(scanQueue, scanRepo, trivyServerURL)
	go worker.StartJobWorker(jobQueue, jobRepo, trivyServerURL)
	log.Println("Workers started")

	// Хендлеры
	scanHandlers := handlers.NewScanHandlers(scanRepo, scanQueue)
	configHandlers := handlers.NewConfigHandlers(configRepo, jobRepo, jobQueue)
	jobHandlers := handlers.NewJobHandlers(jobRepo)
	groupHandlers := handlers.NewGroupHandlers()
	webhookHandlers := handlers.NewWebhookHandlers(configRepo, jobRepo, jobQueue)
	quickHandlers := handlers.NewQuickHandlers(jobRepo, jobQueue) // новый хендлер

	// Маршруты
	router := chi.NewRouter()
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Подключаем API маршруты
	apiRouter := routes.SetupRoutes(&routes.HandlerDeps{
		ScanHandlers:    scanHandlers,
		ConfigHandlers:  configHandlers,
		JobHandlers:     jobHandlers,
		GroupHandlers:   groupHandlers,
		WebhookHandlers: webhookHandlers,
		QuickHandlers:   quickHandlers, // добавляем
	})
	router.Mount("/api/v1", apiRouter)

	// Вывод маршрутов
	log.Println("Registered routes:")
	_ = chi.Walk(router, func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		log.Printf("  %s %s", method, route)
		return nil
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}
