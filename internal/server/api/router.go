package api

import (
	"net/http"

	"github.com/syydee3/Goose-Analyzer/internal/server/config"
	"github.com/syydee3/Goose-Analyzer/internal/server/process"
	"github.com/syydee3/Goose-Analyzer/internal/server/storage"
	"github.com/syydee3/Goose-Analyzer/internal/server/ws"
)

type ServerAPI struct {
	cfg     config.Config
	events  *storage.EventStore
	history *storage.HistoryStore
	procMgr *process.Manager
	wsHub   *ws.Hub
}

func NewRouter(
	cfg config.Config,
	events *storage.EventStore,
	history *storage.HistoryStore,
	procMgr *process.Manager,
	wsHub *ws.Hub,
) http.Handler {
	api := &ServerAPI{
		cfg:     cfg,
		events:  events,
		history: history,
		procMgr: procMgr,
		wsHub:   wsHub,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", api.handleIndex)
	mux.HandleFunc("/ws", api.wsHub.ServeWS)
	mux.HandleFunc("/api/events", api.handleGetEvents)
	mux.HandleFunc("/api/stats", api.handleGetStats)
	mux.HandleFunc("/api/config", api.handleGetConfig)
	mux.HandleFunc("/history", api.handleGetHistory)
	mux.HandleFunc("/upload", api.handleUpload)
	mux.HandleFunc("/select_config", api.handleSelectConfig)
	mux.HandleFunc("/delete_config", api.handleDeleteConfig)
	mux.HandleFunc("/start", api.handleStart)
	mux.HandleFunc("/stop", api.handleStop)
	mux.HandleFunc("/status", api.handleStatus)

	return mux
}
