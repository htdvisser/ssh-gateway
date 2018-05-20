// Package forward implements forwarding SSH sessions to upstream servers.
package forward

import (
	"context"
	"io"
	"sync"

	"github.com/htdvisser/ssh-gateway/pkg/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Requests forwards ssh requests
func Requests(ctx context.Context, target *ssh.Client, requests <-chan *ssh.Request) error {
	return forwardClientRequests(ctx, target, requests)
}

func forwardClientRequests(ctx context.Context, target *ssh.Client, requests <-chan *ssh.Request) error {
	defer target.Close()
	for req := range requests {
		ok, payload, err := target.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return err
		}
		if req.WantReply {
			if err := req.Reply(ok, payload); err != nil {
				return err
			}
		}
		log.FromContext(ctx).Debug("Forward ssh request", zap.String("type", req.Type), zap.Bool("result", ok))
	}
	return nil
}

type channel struct {
	ctx            context.Context
	sourceChannel  ssh.Channel
	targetChannel  ssh.Channel
	sourceRequests <-chan *ssh.Request
	targetRequests <-chan *ssh.Request
	isShell        bool
}

func (c *channel) handle(ctx context.Context) {
	logger := log.FromContext(ctx)

	logger.Debug("Accept channel")
	defer logger.Debug("Close channel")

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-innerCtx.Done()
		if ctx.Err() != nil && c.isShell {
			logger.Warn("Notify shell")
			c.sourceChannel.Write([]byte("\r\nWARNING: SSH Gateway is stopping.\r\n")) // nolint:gas
		}
	}()

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		c.forwardChannelRequests(ctx, c.sourceChannel, c.targetRequests) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		c.forwardChannelRequests(ctx, c.targetChannel, c.sourceRequests) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		defer c.targetChannel.CloseWrite()
		io.Copy(c.targetChannel, c.sourceChannel) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		defer c.sourceChannel.CloseWrite()
		io.Copy(c.sourceChannel, c.targetChannel) // nolint:gas
	}()
	wg.Wait()
}

func (c *channel) forwardChannelRequests(ctx context.Context, target ssh.Channel, requests <-chan *ssh.Request) error {
	defer target.Close()
	for req := range requests {
		ok, err := target.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return err
		}
		if req.WantReply {
			if err := req.Reply(ok, nil); err != nil {
				return err
			}
		}
		log.FromContext(ctx).Debug("Forward channel request", zap.String("type", req.Type), zap.Bool("result", ok))
		if req.Type == "shell" && ok {
			c.isShell = true
		}
	}
	return nil
}

// Channels forwards ssh channels
func Channels(ctx context.Context, target *ssh.Client, requests <-chan ssh.NewChannel) error {
	return forwardChannels(ctx, target, requests)
}

func forwardChannels(ctx context.Context, target *ssh.Client, channels <-chan ssh.NewChannel) error {
	logger := log.FromContext(ctx)
	for newChannel := range channels {
		if ctx.Err() != nil {
			if err := newChannel.Reject(ssh.Prohibited, ctx.Err().Error()); err != nil {
				return err
			}
			return ctx.Err()
		}
		targetChannel, targetRequests, err := target.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err, ok := err.(*ssh.OpenChannelError); ok {
			if err := newChannel.Reject(err.Reason, err.Message); err != nil {
				return err
			}
			return err
		}
		sourceChannel, sourceRequests, err := newChannel.Accept()
		if err != nil {
			logger.Error("Could not accept channel", zap.Error(err))
			continue
		}
		channel := &channel{
			sourceChannel:  sourceChannel,
			sourceRequests: sourceRequests,
			targetChannel:  targetChannel,
			targetRequests: targetRequests,
		}
		go channel.handle(log.NewContext(ctx, logger.With(zap.String("type", newChannel.ChannelType()))))
	}
	return nil
}
