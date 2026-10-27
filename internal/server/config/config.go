package config

import "os"

type Config struct {
	TCPAddr        string
	HTTPAddr       string
	UploadDir      string
	ConfigDir      string
	HistoryFile    string
	AnalyzerBin    string
	DefaultDump    string
	MaxMemoryItems int
}

func Load() Config {
	return Config{
		TCPAddr:        getEnv("TCP_ADDR", "0.0.0.0:5514"),
		HTTPAddr:       getEnv("HTTP_ADDR", "0.0.0.0:5000"),
		UploadDir:      getEnv("UPLOAD_DIR", "uploads"),
		ConfigDir:      getEnv("CONFIG_DIR", "configs"),
		HistoryFile:    getEnv("HISTORY_FILE", "configs/history.json"),
		AnalyzerBin:    getEnv("ANALYZER_BIN", "./bin/analyzer"),
		DefaultDump:    getEnv("DEFAULT_DUMP", "/root/dumps/nergenA1_A2dump_nodup.pcapng"),
		MaxMemoryItems: 2000,
	}
}

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
