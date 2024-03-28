package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sync/errgroup"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	if err := run(log); err != nil {
		log.Error("Failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	socksServer, err := NewSocks5Server(log.With("type", "socks5"), socksPort)
	if err != nil {
		return fmt.Errorf("creating socks5 server: %w", err)
	}
	httpServer := newHTTPProxyServer(log.With("type", "http"), httpPort)
	g, _ := errgroup.WithContext(context.Background())
	g.Go(socksServer.Serve)
	g.Go(httpServer.ListenAndServe)
	return g.Wait()
}

const (
	httpPort  = 30000
	socksPort = 30001
)
