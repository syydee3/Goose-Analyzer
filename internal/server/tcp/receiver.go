package tcp

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"strings"

	"github.com/syydee3/Goose-Analyzer/internal/server/storage"
	"github.com/syydee3/Goose-Analyzer/internal/server/ws"
	"github.com/syydee3/Goose-Analyzer/pkg/models"
)

type Receiver struct {
	addr  string
	store *storage.EventStore
	wsHub *ws.Hub
}

func NewReceiver(addr string, store *storage.EventStore, wsHub *ws.Hub) *Receiver {
	return &Receiver{
		addr:  addr,
		store: store,
		wsHub: wsHub,
	}
}

func (r *Receiver) ListenAndServe() error {
	listener, err := net.Listen("tcp", r.addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCP accept error: %v", err)
			continue
		}
		go r.handleConn(conn)
	}
}

func (r *Receiver) handleConn(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, '{')
		if idx == -1 {
			continue
		}
		var ev models.AlertEvent
		if err := json.Unmarshal([]byte(line[idx:]), &ev); err != nil {
			log.Printf("TCP JSON parse error: %v", err)
			continue
		}
		normalized := r.store.Add(ev)
		r.wsHub.BroadcastEvent(normalized)
	}
}
