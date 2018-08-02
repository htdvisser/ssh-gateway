// Package cmd implements dispatching commands on the SSH gateway using SSH's
// "exec" requests.
package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"go.htdvisser.nl/ssh-gateway/pkg/encoding"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Command is the function signature of a command. It has access to the permissions
// of the connected user, the environment set by the connected user, and it can
// read/write to the channel.
type Command func(ctx context.Context, conn *ssh.Permissions, env map[string]string, rw io.ReadWriter) error

// Dispatcher is a collection of named commands.
type Dispatcher map[string]Command

// Dispatch dispatches commands.
func (r Dispatcher) Dispatch(ctx context.Context, sshConn *ssh.ServerConn, sshChannels <-chan ssh.NewChannel, sshRequests <-chan *ssh.Request) error {
	logger := log.FromContext(ctx)
	go ssh.DiscardRequests(sshRequests)
	for newChannel := range sshChannels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			logger.Warn("Could not accept channel", zap.Error(err))
			return err
		}
		go func() {
			defer channel.Close()
			scanner := bufio.NewScanner(channel)
			for scanner.Scan() {
				fmt.Println(scanner.Text()) // Println will add back the final '\n'
			}
			if err := scanner.Err(); err != nil {
				logger.Warn("scanner err", zap.Error(err))
			}
		}()
		env := make(map[string]string)
		for req := range channelRequests {
			switch req.Type {
			case "pty-req":
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
				fmt.Fprint(channel, "No shell available.\r\n")
				channel.Close()
			case "env":
				k, rest, ok := encoding.ParseString(req.Payload)
				if !ok {
					continue
				}
				v, rest, ok := encoding.ParseString(rest)
				if !ok {
					continue
				}
				env[string(k)] = string(v)
				if len(rest) == 0 {
					req.Reply(true, nil)
				}
			case "exec":
				cmdBytes, rest, ok := encoding.ParseString(req.Payload)
				if !ok {
					continue
				}
				if len(rest) != 0 {
					req.Reply(false, nil)
				}
				cmdName := string(cmdBytes)
				logger = logger.With(zap.String("command", cmdName))
				cmd, ok := r[cmdName]
				req.Reply(ok, nil)
				if !ok {
					continue
				}
				logger.Debug("Dispatching command")
				err := cmd(ctx, sshConn.Permissions, env, channel)
				if err == nil {
					logger.Info("Executed command")
					channel.SendRequest("exit-status", false, encoding.Uint32(0))
				} else {
					logger.Warn("Executed command", zap.Error(err))
					channel.SendRequest("exit-status", false, encoding.Uint32(1))
				}
				channel.Close()
			default:
				logger.Warn(
					"unknown channel request",
					zap.String("request_type", req.Type),
					zap.Bool("want_reply", req.WantReply),
					zap.ByteString("request_payload", req.Payload),
				)
				req.Reply(false, nil)
			}
		}
	}
	return nil
}
