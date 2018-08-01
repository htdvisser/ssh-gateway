package cmd

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ListUpstreams lists the upstreams that the connected user is allowed to connect to.
func ListUpstreams(dataDir string) Command {
	return func(ctx context.Context, permissions *ssh.Permissions, env map[string]string, rw io.ReadWriter) error {
		var upstreams []string
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
			authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKeyBytes)
			if err != nil {
				return err
			}
			if permissions.Extensions["pubkey-fp"] != ssh.FingerprintSHA256(authorizedKey) {
				continue
			}
			upstreams = append(upstreams, filepath.Base(filepath.Dir(authorizedKeyFile)))
		}
		fmt.Fprint(rw, strings.Join(upstreams, " "))
		fmt.Fprint(rw, "\r\n")
		return nil
	}
}
