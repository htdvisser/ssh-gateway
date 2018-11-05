package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"go.htdvisser.nl/ssh-gateway/pkg/upstreams"
	"golang.org/x/crypto/ssh"
)

const hostConfig = `Host %[1]s
  HostName %[2]s
  Port %[3]s
  User %[1]s
`

var (
	sshHost = or(os.Getenv("SSH_HOST"), "$SSH_HOST")
	sshPort = or(os.Getenv("SSH_PORT"), "$SSH_PORT")
)

func or(str ...string) string {
	for _, str := range str {
		if str != "" {
			return str
		}
	}
	return ""
}

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
// If the SSH gateway has the SSH_HOST and SSH_PORT preconfigured, you can update
// the SSH config as follows:
//
//     ssh -p 2222 gateway@localhost config > ~/.ssh/config.d/ssh_gateway
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
			configs = append(configs, fmt.Sprintf(hostConfig, upstream, sshHost, sshPort))
		}
		fmt.Fprint(rw, strings.Join(configs, "\n"))
		fmt.Fprint(rw, "\r\n")
		return nil
	}
}
