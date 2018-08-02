package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

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
//     ssh -p 2222 root@localhost config | sed -e 's/$SSH_HOST/localhost/g' -e 's/$SSH_PORT/2222/g' > ~/.ssh/config.d/ssh_gateway
//
// You should obviously replace the host "localhost" and port "2222" if that is
// different in your deployment.
func UpstreamConfig(dataDir string) Command {
	return func(ctx context.Context, permissions *ssh.Permissions, env map[string]string, rw io.ReadWriter) error {
		var configs []string
		glob := filepath.Join(dataDir, "upstreams", "*", "authorized_keys_*")
		authorizedKeyFiles, err := filepath.Glob(glob)
		if err != nil {
			return err
		}
		for _, authorizedKeyFile := range authorizedKeyFiles {
			authorizedKeyBytes, err := ioutil.ReadFile(authorizedKeyFile)
			if err != nil {
				return err
			}
			for _, authorizedKeyBytes := range bytes.Split(authorizedKeyBytes, []byte("\n")) {
				if len(authorizedKeyBytes) == 0 {
					continue
				}
				authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKeyBytes)
				if err != nil {
					continue
				}
				if permissions.Extensions["pubkey-fp"] != ssh.FingerprintSHA256(authorizedKey) {
					continue
				}
				upstreamName := filepath.Base(filepath.Dir(authorizedKeyFile))
				config := fmt.Sprintf(hostConfig, upstreamName)
				configs = append(configs, config)
			}
		}
		fmt.Fprint(rw, strings.Join(configs, "\n"))
		fmt.Fprint(rw, "\r\n")
		return nil
	}
}
