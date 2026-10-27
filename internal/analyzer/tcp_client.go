package analyzer

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syydee3/Goose-Analyzer/pkg/models"
)

type LoadCounters struct {
	ConfiguredPackets atomic.Uint64
	GhostPackets      atomic.Uint64
	TCPMessagesSent   atomic.Uint64
}

type TCPClient struct {
	serverAddr string
	msgChan    chan string
	wg         sync.WaitGroup
	Counters   LoadCounters
}

func NewTCPClient(serverAddr string, bufferSize int) *TCPClient {
	c := &TCPClient{
		serverAddr: serverAddr,
		msgChan:    make(chan string, bufferSize),
	}
	c.wg.Go(c.sendLoop)
	return c
}

func (c *TCPClient) sendLoop() {
	defer c.wg.Done()
	var conn net.Conn

	connect := func() net.Conn {
		for {
			conn, err := net.DialTimeout("tcp", c.serverAddr, 2*time.Second)
			if err == nil {
				return conn
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	for payload := range c.msgChan {
		for {
			if conn == nil {
				conn = connect()
			}
			_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte(payload + "\n")); err == nil {
				c.Counters.TCPMessagesSent.Add(1)
				break
			}
			_ = conn.Close()
			conn = nil
		}
	}

	if conn != nil {
		_ = conn.Close()
	}
}

func (c *TCPClient) Close() {
	close(c.msgChan)
	c.wg.Wait()
}

func (c *TCPClient) EmitFlag(f models.GooseFlag, g models.GoosePacket) {
	c.Counters.ConfiguredPackets.Add(1)
	if f.NoERR && !f.GhostGoose {
		return
	}
	sevLabel, rfcSev := severityForFlag(f)
	msg := buildFlagErrorText(f)
	if msg == "" {
		msg = "Проверка ошибки GOOSE"
	}
	c.sendPacketError(sevLabel, rfcSev, msg, g)
}

func (c *TCPClient) EmitGhost(g models.GoosePacket) {
	c.Counters.GhostPackets.Add(1)
	c.sendPacketError("warning", 4, "Ghost GOOSE (пакет вне конфигурации)", g)
}

func (c *TCPClient) EmitLoadStats() {
	ev := models.AlertEvent{
		Timestamp: time.Now().UTC().Format("2006-02-02T15:04:05Z"),
		Severity:  "info",
		Error:     "Статистика нагрузки анализатора (снимок)",
		Context: map[string]any{
			"kind":               "analyzer_load_stats",
			"configured_packets": c.Counters.ConfiguredPackets.Load(),
			"ghots_packets":      c.Counters.GhostPackets.Load(),
			"syslog_datagrams":   c.Counters.TCPMessagesSent.Load(),
		},
	}
	b, _ := json.Marshal(ev)
	c.enqueueRFC5424(string(b), 6)
}

func (c *TCPClient) sendPacketError(sevLabel string, rfcSev int, errText string, g models.GoosePacket) {
	ev := models.AlertEvent{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Severity:  sevLabel,
		Error:     errText,
		Context: map[string]any{
			"appid":      fmt.Sprintf("0x%04x", g.AppID),
			"goid":       g.GoID,
			"dst_mac":    fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", g.DstMAC[0], g.DstMAC[1], g.DstMAC[2], g.DstMAC[3], g.DstMAC[4], g.DstMAC[5]),
			"goose_time": gooseTimeToISO(g.Time),
		},
	}
	b, _ := json.Marshal(ev)
	c.enqueueRFC5424(string(b), rfcSev)
}

func (c *TCPClient) enqueueRFC5424(jsonBody string, severity int) {
	pri := 8 + severity
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	c.msgChan <- fmt.Sprintf("<%d>1 %s localhost goose-analyzer - - - %s", pri, ts, jsonBody)
}

func severityForFlag(f models.GooseFlag) (string, int) {
	if f.ClockFailure {
		return "critical", 2
	}
	if !f.NoERR {
		return "error", 4
	}
	return "warning", 4
}

func buildFlagErrorText(f models.GooseFlag) string {
	var parts []string
	add := func(cond bool, text string) {
		if cond {
			parts = append(parts, text)
		}
	}
	add(f.GhostGoose, "GhostGOOSE")
	add(f.DuplicateGoose, "Дублирование пакетов")
	add(f.SqNumErr, "Ошибка sqNum")
	add(f.StNumErr, "Ошибка stNum")
	add(f.ConfRevErr, "Ошибка confRev")
	add(f.ConfRevChng, "Изменение confRev")
	add(f.VidChng, "Изменение VLAN ID")
	add(f.VprChng, "Изменение приоритета VLAN")
	add(f.VlanAdded, "Добавлена метка VLAN")
	add(f.VlanRemoved, "Снята метка VLAN")
	add(f.SrcMacErr, "Изменился MAC источника")
	add(f.ClockRecovery, "Восстановление часов")
	add(f.ClockSync, "Синхронизация часов")
	add(f.ClockInvalidAccuracy, "Недопустимая точность часов")
	add(f.DatasetEmp, "Пустой dataset")
	add(f.NdsComm, "GOOSE need commissioning (ndsComm)")

	if len(parts) == 0 && !f.NoERR {
		return "Нарушение проверки GOOSE"
	}
	return strings.Join(parts, "; ")
}

func gooseTimeToISO(gooseTime int64) string {
	sec := int64(uint64(gooseTime) >> 32)
	frac := uint64(gooseTime>>8) & 0xFFFFFF
	millis := int64((float64(frac)/float64(0x1000000))*1000000.0) / 1000
	return time.Unix(sec, millis*int64(time.Millisecond)).UTC().Format("2006-01-02T15:04:05:000Z")
}
