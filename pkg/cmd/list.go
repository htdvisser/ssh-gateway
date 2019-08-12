package cmd

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.htdvisser.nl/ssh-gateway/pkg/upstreams"
	"golang.org/x/crypto/ssh"
)

// ListUpstreams lists the upstreams that the connected user is allowed to connect to.
func ListUpstreams(dataDir string) Command {
	return func(ctx context.Context, permissions *ssh.Permissions, env map[string]string, rw io.ReadWriter) error {
		upstreams, err := upstreams.List(dataDir, getPublicKey(permissions))
		if err != nil {
			return err
		}
		upstreamNames := make([]string, 0, len(upstreams))
		for upstream := range upstreams {
			upstreamNames = append(upstreamNames, upstream)
		}
		sort.Strings(upstreamNames)
		fmt.Fprint(rw, strings.Join(upstreamNames, " "))
		fmt.Fprint(rw, "\r\n")
		return nil
	}
}
