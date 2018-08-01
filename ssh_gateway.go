// Package ssh implements the main logic for the ssh-gateway program.
package ssh // import "go.htdvisser.nl/ssh-gateway"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"regexp"
	"time"

	"go.htdvisser.nl/ssh-gateway/pkg/forward"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v2"
)

// Name to be used as SSH Client/Server name.
const Name = "Gateway"

type upstreamConfig struct {
	Host        string       `yaml:"host"`
	Port        uint         `yaml:"port"`
	User        string       `yaml:"user"`
	Password    string       `yaml:"password"`
	PrivateKeys []ssh.Signer `yaml:"-"`
}

func (c upstreamConfig) AuthMethods() (methods []ssh.AuthMethod) {
	if len(c.PrivateKeys) > 0 {
		methods = append(methods, ssh.PublicKeys(c.PrivateKeys...))
	}
	if c.Password != "" {
		methods = append(methods, ssh.Password(c.Password))
	}
	return
}

// NewGateway instantiates a new SSH Gateway.
func NewGateway(ctx context.Context, dataDir string) *Gateway {
	return &Gateway{ctx: ctx, dataDir: dataDir}
}

// Gateway implements an SSH Gateway.
type Gateway struct {
	ctx          context.Context
	dataDir      string
	cfg          *ssh.ServerConfig
	identityKeys []ssh.Signer
}

var userRegexp = regexp.MustCompile("^[a-z0-9._-]+$")

func (gtw *Gateway) bannerCallback(c ssh.ConnMetadata) string {
	return fmt.Sprintf("You are connecting as %s from %s...\n", c.User(), c.RemoteAddr())
}

func (gtw *Gateway) publicKeyCallback(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	if !userRegexp.MatchString(c.User()) {
		return nil, errors.New("invalid username")
	}
	authorizedKeyFiles, err := filepath.Glob(filepath.Join(gtw.dataDir, "upstreams", c.User(), "authorized_key*"))
	if err != nil {
		return nil, err
	}
	if len(authorizedKeyFiles) == 0 {
		return nil, errors.New("no network matches username")
	}
	marshaledPubKey := pubKey.Marshal()
	for _, authorizedKeyFile := range authorizedKeyFiles {
		authorizedKeyBytes, err := ioutil.ReadFile(authorizedKeyFile)
		if err != nil {
			return nil, err
		}
		authorizedKey, comment, _, _, err := ssh.ParseAuthorizedKey(authorizedKeyBytes)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(authorizedKey.Marshal(), marshaledPubKey) {
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey-name":    filepath.Base(authorizedKeyFile),
					"pubkey-comment": comment,
					"pubkey-fp":      ssh.FingerprintSHA256(pubKey),
				},
			}, nil
		}
	}
	return nil, errors.New("no match for pubKey")
}

// LoadConfig loads the configuration for the SSH Gateway.
func (gtw *Gateway) LoadConfig() error {
	logger := log.FromContext(gtw.ctx)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: gtw.publicKeyCallback,
		ServerVersion:     "SSH-2.0-" + Name,
		BannerCallback:    gtw.bannerCallback,
	}
	identityFiles, err := filepath.Glob(filepath.Join(gtw.dataDir, "server", "id_*"))
	if err != nil {
		return err
	}
	for _, identityFile := range identityFiles {
		if filepath.Ext(identityFile) == ".pub" {
			continue
		}
		identityBytes, err := ioutil.ReadFile(identityFile)
		if err != nil {
			return err
		}
		identityKey, err := ssh.ParsePrivateKey(identityBytes)
		if err != nil {
			return err
		}
		logger.Debug("Add server identity", zap.String("file", identityFile))
		gtw.identityKeys = append(gtw.identityKeys, identityKey)
	}
	hostKeyFiles, err := filepath.Glob(filepath.Join(gtw.dataDir, "server", "ssh_host_*"))
	if err != nil {
		return err
	}
	for _, hostKeyFile := range hostKeyFiles {
		if filepath.Ext(hostKeyFile) == ".pub" {
			continue
		}
		hostKeyBytes, err := ioutil.ReadFile(hostKeyFile)
		if err != nil {
			return err
		}
		hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
		if err != nil {
			return err
		}
		logger.Debug("Add host key", zap.String("file", hostKeyFile))
		cfg.AddHostKey(hostKey)
	}
	gtw.cfg = cfg
	return nil
}

// Handle handles a new connection.
func (gtw *Gateway) Handle(conn net.Conn) {
	logger := log.FromContext(gtw.ctx)

	defer conn.Close()
	sshConn, sshChannels, sshRequests, err := ssh.NewServerConn(conn, gtw.cfg)
	if err != nil {
		logger.Warn("Could not accept SSH conn", zap.Error(err))
		return
	}
	defer sshConn.Close()

	logger = logger.With(
		zap.String("upstream", sshConn.User()),
		zap.String("pubkey", sshConn.Permissions.Extensions["pubkey-name"]),
	)

	logger.Info("Accept SSH conn", zap.String("pubkey-comment", sshConn.Permissions.Extensions["pubkey-comment"]))
	defer logger.Info("Close SSH conn")

	configBytes, err := ioutil.ReadFile(filepath.Join(gtw.dataDir, "upstreams", sshConn.User(), "config.yml"))
	if err != nil {
		logger.Warn("Could not read upstream config", zap.Error(err))
		return
	}
	var upstream upstreamConfig
	if err = yaml.Unmarshal(configBytes, &upstream); err != nil {
		logger.Warn("Could not unmarshal upstream config", zap.Error(err))
		return
	}
	if upstream.Port == 0 {
		upstream.Port = 22
	}
	if upstream.User == "" {
		upstream.User = "root"
	}
	if upstream.Password == "" {
		identityFiles, err := filepath.Glob(filepath.Join(gtw.dataDir, "upstreams", sshConn.User(), "id_*"))
		if err != nil {
			logger.Warn("Could not list upstream identity files", zap.Error(err))
			return
		}
		for _, identityFile := range identityFiles {
			if filepath.Ext(identityFile) == ".pub" {
				continue
			}
			identityBytes, err := ioutil.ReadFile(identityFile)
			if err != nil {
				logger.Warn("Could not read upstream identity file", zap.Error(err), zap.String("file", filepath.Base(identityFile)))
				continue
			}
			signer, err := ssh.ParsePrivateKey(identityBytes)
			if err != nil {
				logger.Warn("Could not parse upstream identity file", zap.Error(err), zap.String("file", filepath.Base(identityFile)))
				continue
			}
			logger.Debug("Add upstream identity", zap.String("file", identityFile))
			upstream.PrivateKeys = append(upstream.PrivateKeys, signer)
		}
		if len(upstream.PrivateKeys) == 0 && len(gtw.identityKeys) > 0 {
			upstream.PrivateKeys = append(upstream.PrivateKeys, gtw.identityKeys...)
		}
	}
	var hostKeyCallback ssh.HostKeyCallback
	if hostKeyFiles, err := filepath.Glob(filepath.Join(gtw.dataDir, "upstreams", sshConn.User(), "known_host*")); err == nil && len(hostKeyFiles) > 0 {
		hostKeyCallback, err = knownhosts.New(hostKeyFiles...)
		if err != nil {
			logger.Error("Faild to load known hosts files", zap.Error(err))
		}
	} else {
		logger.Warn("No known_hosts files, will generate...")
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			ioutil.WriteFile(
				filepath.Join(gtw.dataDir, "upstreams", sshConn.User(), "known_host_generated"),
				[]byte(knownhosts.Line([]string{hostname, remote.String()}, key)),
				0644,
			)
			return nil
		}
	}

	addr := fmt.Sprintf("%s:%d", upstream.Host, upstream.Port)

	logger.Info(
		"Connect to upstream",
		zap.String("upstream_user", upstream.User),
		zap.String("upstream_addr", addr),
	)
	sshTarget, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            upstream.User,
		Auth:            upstream.AuthMethods(),
		HostKeyCallback: hostKeyCallback,
		ClientVersion:   "SSH-2.0-" + Name,
		Timeout:         5 * time.Second,
	})
	if err != nil {
		logger.Warn("Could not connect to upstream", zap.Error(err))
		return
	}
	defer sshTarget.Close()

	ctx := log.NewContext(gtw.ctx, logger)

	logger.Info("Start Forwarding")
	go forward.Requests(ctx, sshTarget, sshRequests)
	forward.Channels(ctx, sshTarget, sshChannels)
}
