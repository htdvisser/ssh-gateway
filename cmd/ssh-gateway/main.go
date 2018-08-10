// ssh-gateway is a forward Proxy for SSH Servers.
//
// USAGE:
//    ssh-gateway [global options] command [command options] [arguments...]
//
// COMMANDS:
//      help, h  Shows a list of commands or help for one command
//
// GLOBAL OPTIONS:
//    --debug         Show debug logs [$DEBUG]
//    --listen value  Listen address (default: ":2222") [$LISTEN]
//    --data value    Data directory (default: "./data") [$DATA]
//    --help, -h      show help
//    --version, -v   print the version
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/urfave/cli"
	"go.htdvisser.nl/ssh-gateway"
	"go.htdvisser.nl/ssh-gateway/pkg/cmd"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	version  string
	commit   string
	compiled string

	logConfig = zap.NewProductionConfig()
	logger    *zap.Logger

	app = cli.NewApp()
)

func init() {
	logConfig.DisableCaller = true
	logConfig.DisableStacktrace = true
	logConfig.Encoding = "console"
	logConfig.EncoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	logConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logConfig.EncoderConfig.EncodeTime = nil
	logConfig.OutputPaths = []string{"stdout"}

	app.Name = "ssh-gateway"
	app.HelpName = "ssh-gateway"
	app.Usage = "Forward Proxy for SSH Servers"
	if version != "" {
		app.Version = strings.TrimPrefix(version, "v")
	}
	if commit != "" {
		app.Version += "-" + commit
	}
	if compiled, err := time.Parse(time.RFC3339, compiled); err == nil {
		app.Compiled = compiled
	}
	app.Flags = []cli.Flag{
		cli.BoolFlag{Name: "debug", Usage: "Show debug logs", EnvVar: "DEBUG"},
		cli.StringFlag{Name: "listen", Usage: "Listen address", EnvVar: "LISTEN", Value: ":2222"},
		cli.StringFlag{Name: "data", Usage: "Data directory", EnvVar: "DATA", Value: "./data"},
	}
	app.Action = Run
}

func main() {
	app.Run(os.Args) // nolint:gas
}

// Run the SSH Gateway
func Run(c *cli.Context) error {
	signals := make(chan os.Signal)
	signal.Notify(signals, os.Interrupt, os.Kill, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger, _ = logConfig.Build() // nolint:gas
	if c.Bool("debug") {
		logConfig.Level.SetLevel(zapcore.DebugLevel)
		logger.Debug("Debug logging active")
	}
	ctx = log.NewContext(ctx, logger)

	dataDir, err := filepath.Abs(c.String("data"))
	if err != nil {
		logger.Error("Could not find data dir", zap.Error(err))
		return fmt.Errorf("Could not find data dir: %s", err)
	}

	gtw := ssh.NewGateway(ctx, dataDir)

	err = gtw.LoadConfig()
	if err != nil {
		logger.Error("Could not load config", zap.Error(err))
		return fmt.Errorf("Could not load config: %s", err)
	}

	gtw.RegisterCommand("list", cmd.ListUpstreams(dataDir))
	gtw.RegisterCommand("config", cmd.UpstreamConfig(dataDir))

	var wg sync.WaitGroup
	defer func() {
		logger.Info("Waiting for connections to close...")
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			logger.Info("All connections closed...")
		case sig := <-signals:
			fmt.Println()
			logger.Info("Received signal, forcing exit...", zap.String("signal", sig.String()))
		}
	}()

	lis, err := net.Listen("tcp", c.String("listen"))
	if err != nil {
		logger.Error("Could not listen", zap.Error(err))
		return fmt.Errorf("Could not listen: %s", err)
	}
	defer lis.Close()
	logger.Info("Start accepting connections", zap.String("address", lis.Addr().String()))
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Error("Could not accept client", zap.Error(err))
			}
			wg.Add(1)
			go func() {
				gtw.Handle(conn)
				wg.Done()
			}()
		}
	}()

	for {
		select {
		case sig := <-signals:
			fmt.Println()
			logger.Info("Received signal, exiting...", zap.String("signal", sig.String()))
			cancel()
			return nil
		}
	}
}
