package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bannerfp/internal/api"
	"bannerfp/internal/fingerprint"
)

func main() {
	listen := flag.String("listen", envOr("LISTEN_ADDR", ":8080"), "HTTP listen address")
	rulesDir := flag.String("rules", envOr("RULES_DIR", "rules"), "directory of YAML fingerprint rules")
	healthcheck := flag.Bool("healthcheck", false, "probe local /health and exit (for container HEALTHCHECK)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *healthcheck {
		if err := probeHealth(*listen); err != nil {
			log.Error("healthcheck failed", "err", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	rules, err := fingerprint.LoadRulesDir(*rulesDir)
	if err != nil {
		log.Error("load rules failed", "err", err, "dir", *rulesDir)
		os.Exit(1)
	}
	if len(rules) == 0 {
		log.Error("no rules loaded", "dir", *rulesDir)
		os.Exit(1)
	}
	log.Info("rules loaded", "count", len(rules), "dir", *rulesDir)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(fingerprint.NewEngine(rules), log).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", *listen)
		errCh <- srv.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Error("server exit", "err", err)
			os.Exit(1)
		}
	}
}

func probeHealth(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/health", net.JoinHostPort(host, port)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
