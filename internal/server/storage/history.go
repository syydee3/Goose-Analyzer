package storage

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/syydee3/Goose-Analyzer/pkg/models"
)

type HistoryStore struct {
	mu       sync.Mutex
	filePath string
}

func NewHistoryStore(filePath string) *HistoryStore {
	return &HistoryStore{filePath: filePath}
}

func (h *HistoryStore) Load() []models.HistoryItem {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.loadUnlocked()
}

func (h *HistoryStore) Add(filename, filepath string) []models.HistoryItem {
	h.mu.Lock()
	defer h.mu.Unlock()

	items := h.loadUnlocked()
	var filtered []models.HistoryItem
	for _, item := range items {
		if item.Filename != filename {
			filtered = append(filtered, item)
		}
	}

	newItem := models.HistoryItem{
		Filename:  filename,
		Filepath:  filepath,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}
	filtered = append([]models.HistoryItem{newItem}, filtered...)
	if len(filtered) > 10 {
		filtered = filtered[:10]
	}
	h.saveUnlocked(filtered)
	return filtered
}

func (h *HistoryStore) Delete(filepath string) []models.HistoryItem {
	h.mu.Lock()
	defer h.mu.Unlock()

	items := h.loadUnlocked()
	var updated []models.HistoryItem
	for _, item := range items {
		if item.Filepath != filepath {
			updated = append(updated, item)
		}
	}
	h.saveUnlocked(updated)
	return updated
}

func (h *HistoryStore) loadUnlocked() []models.HistoryItem {
	data, err := os.ReadFile(h.filePath)
	if err != nil {
		return []models.HistoryItem{}
	}
	var items []models.HistoryItem
	if err := json.Unmarshal(data, &items); err != nil {
		return []models.HistoryItem{}
	}
	return items
}

func (h *HistoryStore) saveUnlocked(items []models.HistoryItem) {
	data, _ := json.MarshalIndent(items, "", "  ")
	_ = os.WriteFile(h.filePath, data, 0644)
}
