package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"go.htdvisser.nl/ssh-gateway/pkg/upstreams"
	"golang.org/x/crypto/ssh"
)

const hostConfig = `Host %[1]s
  HostName $SSH_HOST
  Port $SSH_PORT
  User %[1]s
`

// UpstreamConfig generates an SSH config template.
//
// Make sure that you have a directory ~/.ssh/config.d and that you have a line
//
//     Include config.d/*
//
// in your ~/.ssh/config. Then you can update the SSH config as follows:
//
//     ssh -p 2222 gateway@localhost config | sed -e 's/$SSH_HOST/localhost/g' -e 's/$SSH_PORT/2222/g' > ~/.ssh/config.d/ssh_gateway
//
// You should obviously replace the host "localhost" and port "2222" if that is
// different in your deployment.
func UpstreamConfig(dataDir string) Command {
	return func(ctx context.Context, permissions *ssh.Permissions, env map[string]string, rw io.ReadWriter) error {
		upstreams, err := upstreams.List(dataDir, getPublicKey(permissions))
		if err != nil {
			return err
		}
		configs := make([]string, 0, len(upstreams))
		for upstream := range upstreams {
			configs = append(configs, fmt.Sprintf(hostConfig, upstream))
		}
		fmt.Fprint(rw, strings.Join(configs, "\n"))
		fmt.Fprint(rw, "\r\n")
		return nil
	}
}
