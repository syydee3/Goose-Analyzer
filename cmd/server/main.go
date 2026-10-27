package main

import (
	"log"
	"net/http"
	"os"

	"github.com/syydee3/Goose-Analyzer/internal/server/api"
	"github.com/syydee3/Goose-Analyzer/internal/server/config"
	"github.com/syydee3/Goose-Analyzer/internal/server/process"
	"github.com/syydee3/Goose-Analyzer/internal/server/storage"
	"github.com/syydee3/Goose-Analyzer/internal/server/tcp"
	"github.com/syydee3/Goose-Analyzer/internal/server/ws"
)

func main() {
	cfg := config.Load()

	_ = os.MkdirAll(cfg.UploadDir, 0755)
	_ = os.MkdirAll(cfg.ConfigDir, 0755)

	eventStore := storage.NewEventStore(cfg.MaxMemoryItems)
	historyStore := storage.NewHistoryStore(cfg.HistoryFile)
	wsHub := ws.NewHub()

	// Запуск TCP-коллектора
	tcpReceiver := tcp.NewReceiver(cfg.TCPAddr, eventStore, wsHub)
	go func() {
		log.Printf("TCP collector listening on %s", cfg.TCPAddr)
		if err := tcpReceiver.ListenAndServe(); err != nil {
			log.Fatalf("TCP collector error: %v", err)
		}
	}()

	procManager := process.NewManager(cfg.AnalyzerBin, "127.0.0.1:5514", wsHub)
	router := api.NewRouter(cfg, eventStore, historyStore, procManager, wsHub)

	log.Printf("HTTP & WebSocket server listening on http://%s", cfg.HTTPAddr)
	log.Fatal(http.ListenAndServe(cfg.HTTPAddr, router))
}
