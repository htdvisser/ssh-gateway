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
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli"
	"go.htdvisser.nl/ssh-gateway"
	"go.htdvisser.nl/ssh-gateway/pkg/cmd"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.htdvisser.nl/ssh-gateway/pkg/metrics"
	"go.htdvisser.nl/ssh-gateway/pkg/slack"
	"go.htdvisser.nl/ssh-gateway/pkg/upstreams"
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
	logConfig.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
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
		cli.StringFlag{Name: "listen-http", Usage: "Listen address for HTTP endpoints", EnvVar: "LISTEN_HTTP", Value: "localhost:12222"},
		cli.StringFlag{Name: "data", Usage: "Data directory", EnvVar: "DATA", Value: "./data"},
		cli.StringFlag{Name: "default-user", Usage: "Default username to use on upstream servers", EnvVar: "DEFAULT_USER"},
		cli.StringFlag{Name: "command-user", Usage: "Username for command execution", EnvVar: "COMMAND_USER"},
		cli.StringFlag{Name: "slack-url", Usage: "URL for Slack notifications", EnvVar: "SLACK_URL"},
	}
	app.Action = Run
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

// Run the SSH Gateway
func Run(c *cli.Context) error {
	signals := make(chan os.Signal)
	signal.Notify(signals, os.Interrupt, os.Kill, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var err error
	logger, err = logConfig.Build()
	if err != nil {
		return err
	}
	if c.Bool("debug") {
		logConfig.Level.SetLevel(zapcore.DebugLevel)
		logger.Debug("Debug logging active")
	}
	ctx = log.NewContext(ctx, logger)

	dataDir, err := filepath.Abs(c.String("data"))
	if err != nil {
		logger.Error("Could not find data dir", zap.Error(err))
		return fmt.Errorf("Could not find data dir: %w", err)
	}

	gtw := ssh.NewGateway(ctx, dataDir)

	err = gtw.LoadConfig()
	if err != nil {
		logger.Error("Could not load config", zap.Error(err))
		return fmt.Errorf("Could not load config: %w", err)
	}

	allUpstreams, err := upstreams.All(dataDir)
	if err != nil {
		logger.Error("Could not load upstreams", zap.Error(err))
		return fmt.Errorf("Could not load upstreams: %w", err)
	}
	for _, upstream := range allUpstreams {
		metrics.InitUpstream(upstream)
		allAuthorized, err := upstreams.ListAuthorized(dataDir, upstream)
		if err != nil {
			logger.Error("Could not load authorized keys for upstream", zap.String("upstream", upstream), zap.Error(err))
			return fmt.Errorf("Could not load authorized keys for upstream %s: %s", upstream, err)
		}
		for _, authorized := range allAuthorized {
			metrics.InitForward(authorized, upstream)
		}
	}

	if defaultUser := c.String("default-user"); defaultUser != "" {
		gtw.SetDefaultUser(defaultUser)
	}

	if commandUser := c.String("command-user"); commandUser != "" {
		gtw.SetCommandUser(commandUser)
	}

	gtw.RegisterCommand("list", cmd.ListUpstreams(dataDir))
	gtw.RegisterCommand("config", cmd.UpstreamConfig(dataDir))

	if slackURL := c.String("slack-url"); slackURL != "" {
		gtw.SetSlackNotifier(&slack.Notifier{
			URL: slackURL,
		})
	}

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

	http.Handle("/metrics", promhttp.Handler())
	lis, err := net.Listen("tcp", c.String("listen"))
	if err != nil {
		logger.Error("Could not listen for SSH", zap.Error(err))
		return fmt.Errorf("Could not listen for SSH: %w", err)
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
				continue
			}
			wg.Add(1)
			go func() {
				gtw.Handle(conn)
				wg.Done()
			}()
		}
	}()

	httpLis, err := net.Listen("tcp", c.String("listen-http"))
	if err != nil {
		logger.Error("Could not listen for HTTP", zap.Error(err))
		return fmt.Errorf("Could not listen for HTTP: %w", err)
	}
	defer httpLis.Close()
	go http.Serve(httpLis, nil)

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
