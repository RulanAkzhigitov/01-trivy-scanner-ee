package db

import (
	"database/sql"
	"time"
	"log"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func Init(databaseURL string) error {
	var err error
	maxAttempts := 10
	for i := 1; i <= maxAttempts; i++ {
		DB, err = sql.Open("postgres", databaseURL)
		if err != nil {
			log.Printf("Attempt %d: failed to open DB: %v", i, err)
			time.Sleep(2 * time.Second)
			continue
		}
		err = DB.Ping()
		if err == nil {
			log.Println("Successfully connected to DB")
			return nil
		}
		log.Printf("Attempt %d: ping failed: %v", i, err)
		DB.Close()
		time.Sleep(2 * time.Second)
	}
	return err
}