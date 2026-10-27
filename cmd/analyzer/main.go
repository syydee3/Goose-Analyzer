package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/syydee3/Goose-Analyzer/internal/analyzer"
	"github.com/syydee3/Goose-Analyzer/internal/scl"
)

func main() {
	sclFile := "nergen_SHSO1_ENMV1_A2.scd"
	dumpFile := "/root/dumps/nergenA1_A2dump_nodup.pcapng"
	onlineMode := true

	if len(os.Args) > 1 {
		sclFile = os.Args[1]
	}
	if len(os.Args) > 2 {
		dumpFile = os.Args[2]
		onlineMode = false
	}

	tcpServer := os.Getenv("ANALYZER_TCP_SERVER")
	if tcpServer == "" {
		tcpServer = "127.0.0.1:5514"
	}
	iface := os.Getenv("ANALYZER_IFACE")
	if iface == "" {
		iface = "eth0"
	}

	cfg, err := scl.LoadConfig(sclFile)
	if err != nil || len(cfg) == 0 {
		fmt.Fprintf(os.Stderr, "Failed to load config %s: %v\n", sclFile, err)
		os.Exit(1)
	}

	handle, err := analyzer.OpenPcap(onlineMode, iface, dumpFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pcap error: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	tcpClient := analyzer.NewTCPClient(tcpServer, 8192)
	defer tcpClient.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
		handle.Close()
	}()

	engine := analyzer.NewEngine(cfg, tcpClient, handle)
	engine.Run(ctx)
}
