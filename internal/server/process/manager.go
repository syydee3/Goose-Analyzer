package process

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/syydee3/Goose-Analyzer/internal/server/ws"
)

type Manager struct {
	mu          sync.Mutex
	analyzerBin string
	tcpTarget   string
	wsHub       *ws.Hub
	procs       map[string]*exec.Cmd
}

func NewManager(analyzerBin, tcpTarget string, wsHub *ws.Hub) *Manager {
	return &Manager{
		analyzerBin: analyzerBin,
		tcpTarget:   tcpTarget,
		wsHub:       wsHub,
		procs:       make(map[string]*exec.Cmd),
	}
}

func (m *Manager) Start(configPath string, dumpPath string) (string, error) {
	args := []string{configPath}
	if dumpPath != "" {
		args = append(args, dumpPath)
	}

	sessionID := time.Now().Format("20060102_150405.000000")
	cmd := exec.Command(m.analyzerBin, args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("ANALYZER_TCP_SERVER=%s", m.tcpTarget))

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return "", err
	}

	m.mu.Lock()
	m.procs[sessionID] = cmd
	m.mu.Unlock()

	go m.streamProcessOutput(sessionID, cmd, stdoutPipe)

	return sessionID, nil
}

func (m *Manager) streamProcessOutput(sessionID string, cmd *exec.Cmd, pipe io.ReadCloser) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text() + "\n"
		m.wsHub.BroadcastOutput(sessionID, line)
	}
	_ = cmd.Wait()
	m.wsHub.BroadcastOutput(sessionID, "\n--- Analyzer finished ---\n")

	m.mu.Lock()
	delete(m.procs, sessionID)
	m.mu.Unlock()
}

func (m *Manager) Stop(sessionID string) error {
	m.mu.Lock()
	cmd, ok := m.procs[sessionID]
	m.mu.Unlock()

	if !ok || cmd.Process == nil {
		return fmt.Errorf("no active process found")
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)

	for i := 0; i < 15; i++ {
		m.mu.Lock()
		_, active := m.procs[sessionID]
		m.mu.Unlock()
		if !active {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return cmd.Process.Kill()
}

func (m *Manager) ActiveSessions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.procs))
	for k := range m.procs {
		out = append(out, k)
	}
	return out
}
