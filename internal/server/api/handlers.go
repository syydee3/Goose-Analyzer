package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var safeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func (a *ServerAPI) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat("templates/index.html"); err == nil {
		http.ServeFile(w, r, "templates/index.html")
		return
	}
	http.ServeFile(w, r, "index.html")
}

func (a *ServerAPI) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	sev := r.URL.Query().Get("severity")
	events := a.events.List(limit, sev)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"errors": events,
		"events": events,
		"count":  len(events),
		"source": "go_tcp_server",
	})
}

func (a *ServerAPI) handleGetStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.events.Stats())
}

func (a *ServerAPI) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tcp_addr": a.cfg.TCPAddr,
	})
}

func (a *ServerAPI) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.history.Load())
}

func (a *ServerAPI) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 50*1024*1024)
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	if !strings.HasSuffix(strings.ToLower(header.Filename), ".scd") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Only .scd files are allowed"})
		return
	}

	filename := safeFilenameRe.ReplaceAllString(filepath.Base(header.Filename), "_")
	var targetPath string
	for _, item := range a.history.Load() {
		if item.Filename == filename {
			targetPath = item.Filepath
			break
		}
	}

	var msg string
	if targetPath != "" && fileExists(targetPath) {
		if err := saveFile(file, targetPath); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		msg = fmt.Sprintf("File '%s' already exists - overwritten", filename)
	} else {
		ts := time.Now().Format("20060102_150405")
		targetPath = filepath.Join(a.cfg.UploadDir, fmt.Sprintf("%s_%s", ts, filename))
		if err := saveFile(file, targetPath); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		msg = fmt.Sprintf("File '%s' uploaded successfully", filename)
		a.history.Add(filename, targetPath)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"filename": filename,
		"filepath": targetPath,
		"message":  msg,
		"history":  a.history.Load(),
	})
}

func (a *ServerAPI) handleSelectConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filepath string `json:"filepath"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Filepath == "" || !fileExists(req.Filepath) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Config file not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"filepath": req.Filepath,
	})
}

func (a *ServerAPI) handleDeleteConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filepath string `json:"filepath"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	updated := a.history.Delete(req.Filepath)
	if req.Filepath != "" && fileExists(req.Filepath) {
		_ = os.Remove(req.Filepath)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"history": updated,
	})
}

func (a *ServerAPI) handleStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConfigPath string `json:"config_path"`
		Mode       string `json:"mode"`
		DumpPath   string `json:"dump_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	absConfig, err := filepath.Abs(req.ConfigPath)
	if err != nil || !fileExists(absConfig) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Config file not found"})
		return
	}

	var dumpPath string
	if req.Mode != "online" {
		dumpPath = strings.TrimSpace(req.DumpPath)
		if dumpPath == "" || !fileExists(dumpPath) {
			dumpPath = a.cfg.DefaultDump
			if !fileExists(dumpPath) {
				writeJSON(w, http.StatusNotFound, map[string]string{
					"error": fmt.Sprintf("Dump file not found: %s", dumpPath),
				})
				return
			}
		}
	}

	sessionID, err := a.procMgr.Start(absConfig, dumpPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"session_id": sessionID,
		"message":    fmt.Sprintf("Analyzer started with config: %s", absConfig),
	})
}

func (a *ServerAPI) handleStop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := a.procMgr.Stop(req.SessionID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Process terminated",
	})
}

func (a *ServerAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_sessions": a.procMgr.ActiveSessions(),
	})
}

func saveFile(src io.Reader, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
