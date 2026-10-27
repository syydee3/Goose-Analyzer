package storage

import (
	"strings"
	"sync"

	"github.com/syydee3/Goose-Analyzer/pkg/models"
)

type EventStore struct {
	mu         sync.RWMutex
	maxItems   int
	events     []models.AlertEvent
	total      int
	bySeverity map[string]int
}

func NewEventStore(maxItems int) *EventStore {
	return &EventStore{
		maxItems:   maxItems,
		events:     make([]models.AlertEvent, 0, maxItems),
		bySeverity: make(map[string]int),
	}
}

func (s *EventStore) Add(ev models.AlertEvent) models.AlertEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ev.Message == "" {
		ev.Message = ev.Error
	}
	if ev.Error == "" {
		ev.Error = ev.Message
	}
	sev := strings.ToLower(strings.TrimSpace(ev.Severity))
	if sev == "" {
		sev = "error"
	}
	ev.Severity = sev

	s.total++
	s.bySeverity[sev]++

	if len(s.events) >= s.maxItems {
		s.events = s.events[1:]
	}
	s.events = append(s.events, ev)
	return ev
}

func (s *EventStore) List(limit int, severityFilter string) []models.AlertEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sev := strings.ToLower(strings.TrimSpace(severityFilter))
	var out []models.AlertEvent
	for _, ev := range s.events {
		if sev != "" && ev.Severity != sev {
			continue
		}
		out = append(out, ev)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func (s *EventStore) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bySev := make(map[string]int, len(s.bySeverity))
	for k, v := range s.bySeverity {
		bySev[k] = v
	}
	return map[string]interface{}{
		"total":       s.total,
		"by_severity": bySev,
	}
}
