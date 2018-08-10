package upstreams

import (
	"bytes"
	"errors"
	"io/ioutil"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

type Authorization struct {
	Filename string
	ssh.PublicKey
	Comment string
}

func matchingAuthorizedKeyFiles(publicKey ssh.PublicKey, authorizedKeyFiles ...string) (matches []Authorization) {
	for _, authorizedKeyFile := range authorizedKeyFiles {
		authorizedKeyBytes, err := ioutil.ReadFile(authorizedKeyFile)
		if err != nil {
			continue
		}
		for _, authorizedKeyBytes := range bytes.Split(authorizedKeyBytes, []byte("\n")) {
			if len(authorizedKeyBytes) == 0 {
				continue
			}
			authorizedKey, comment, _, _, err := ssh.ParseAuthorizedKey(authorizedKeyBytes)
			if err != nil {
				continue
			}
			if !bytes.Equal(publicKey.Marshal(), authorizedKey.Marshal()) {
				continue
			}
			matches = append(matches, Authorization{
				Filename:  authorizedKeyFile,
				PublicKey: authorizedKey,
				Comment:   comment,
			})
		}
	}
	return
}

// ErrNotAuthorized means that the public key is not authorized.
var ErrNotAuthorized = errors.New("not authorized")

// Authorized returns the authorizations of the given public key on the given upstream.
func Authorized(dataDir string, publicKey ssh.PublicKey, upstream string) (*Authorization, error) {
	if publicKey == nil {
		return nil, ErrNotAuthorized
	}

	authorizedKeyFiles, err := filepath.Glob(filepath.Join(dataDir, "upstreams", upstream, "authorized_keys_*"))
	if err != nil {
		return nil, err
	}
	matches := matchingAuthorizedKeyFiles(publicKey, authorizedKeyFiles...)
	if len(matches) > 0 {
		return &matches[0], nil
	}
	return nil, ErrNotAuthorized
}

// AlwaysAuthorized returns whether the given public key provides access to any upstream.
func AlwaysAuthorized(dataDir string, publicKey ssh.PublicKey) (*Authorization, error) {
	if publicKey == nil {
		return nil, ErrNotAuthorized
	}

	alwaysAuthorizedKeyFiles, err := filepath.Glob(filepath.Join(dataDir, "server", "authorized_keys_*"))
	if err != nil {
		return nil, err
	}
	matches := matchingAuthorizedKeyFiles(publicKey, alwaysAuthorizedKeyFiles...)
	if len(matches) > 0 {
		return &matches[0], nil
	}
	return nil, ErrNotAuthorized
}

// List upstreams that are accessible with the given public key.
func List(dataDir string, publicKey ssh.PublicKey) (map[string]*Authorization, error) {
	alwaysAuthorized, err := AlwaysAuthorized(dataDir, publicKey)
	if err != nil && err != ErrNotAuthorized {
		return nil, err
	}

	upstreamConfigs, err := filepath.Glob(filepath.Join(dataDir, "upstreams", "*", "config.yml"))
	if err != nil {
		return nil, err
	}

	var upstreams = make(map[string]*Authorization, len(upstreamConfigs))
	for _, upstreamConfig := range upstreamConfigs {
		upstream := filepath.Base(filepath.Dir(upstreamConfig))
		if alwaysAuthorized != nil {
			upstreams[upstream] = alwaysAuthorized
			continue
		}
		authorized, err := Authorized(dataDir, publicKey, upstream)
		if err != nil && err != ErrNotAuthorized {
			return nil, err
		}
		if authorized != nil {
			upstreams[upstream] = authorized
		}
	}

	return upstreams, nil
}
