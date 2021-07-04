package upstreams

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/crypto/ssh"
)

type Authorization struct {
	Filename string
	ssh.PublicKey
	Comment string
}

func matchingAuthorizedKeyFiles(publicKey ssh.PublicKey, authorizedKeyFiles ...string) (matches []Authorization, err error) {
	for _, authorizedKeyFile := range authorizedKeyFiles {
		authorizedKeyBytes, err := ioutil.ReadFile(authorizedKeyFile)
		if err != nil {
			return nil, err
		}
		for _, authorizedKeyBytes := range bytes.Split(authorizedKeyBytes, []byte("\n")) {
			if len(authorizedKeyBytes) == 0 {
				continue
			}
			authorizedKey, comment, _, _, err := ssh.ParseAuthorizedKey(authorizedKeyBytes)
			if err != nil {
				return nil, err
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

func filesInDir(dir string, match string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matched, err := filepath.Match(match, entry.Name())
		if err != nil {
			return nil, err
		}
		if matched {
			results = append(results, filepath.Join(dir, entry.Name()))
		}
	}
	return results, nil
}

// ErrNotAuthorized means that the public key is not authorized.
var ErrNotAuthorized = errors.New("not authorized")

// Authorized returns the authorizations of the given public key on the given upstream.
func Authorized(dataDir string, publicKey ssh.PublicKey, upstream string) (*Authorization, error) {
	if publicKey == nil {
		return nil, ErrNotAuthorized
	}

	authorizedKeyFiles, err := filesInDir(filepath.Join(dataDir, "upstreams", upstream), "authorized_keys_*")
	if err != nil {
		return nil, err
	}
	matches, err := matchingAuthorizedKeyFiles(publicKey, authorizedKeyFiles...)
	if err != nil {
		return nil, err
	}
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

	alwaysAuthorizedKeyFiles, err := filesInDir(filepath.Join(dataDir, "server"), "authorized_keys_*")
	if err != nil {
		return nil, err
	}
	matches, err := matchingAuthorizedKeyFiles(publicKey, alwaysAuthorizedKeyFiles...)
	if err != nil {
		return nil, err
	}
	if len(matches) > 0 {
		return &matches[0], nil
	}
	return nil, ErrNotAuthorized
}

func dirsInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, entry := range entries {
		if entry.IsDir() {
			results = append(results, filepath.Join(dir, entry.Name()))
		}
	}
	return results, nil
}

// List upstreams that are accessible with the given public key.
func List(dataDir string, publicKey ssh.PublicKey) (map[string]*Authorization, error) {
	alwaysAuthorized, err := AlwaysAuthorized(dataDir, publicKey)
	if err != nil && err != ErrNotAuthorized {
		return nil, err
	}

	upstreamDirs, err := dirsInDir(filepath.Join(dataDir, "upstreams"))
	if err != nil {
		return nil, err
	}

	upstreams := make(map[string]*Authorization, len(upstreamDirs))
	for _, upstreamDir := range upstreamDirs {
		upstream := filepath.Base(upstreamDir)
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

// All returns the names of all upstreams.
func All(dataDir string) ([]string, error) {
	upstreamDirs, err := dirsInDir(filepath.Join(dataDir, "upstreams"))
	if err != nil {
		return nil, err
	}
	all := make([]string, len(upstreamDirs))
	for i, upstreamDir := range upstreamDirs {
		all[i] = filepath.Base(upstreamDir)
	}
	sort.Strings(all)
	return all, nil
}

// ListAuthorized returns the authorized key names for the given upstream.
func ListAuthorized(dataDir, upstream string) ([]string, error) {
	authorized := make(map[string]struct{})
	alwaysAuthorizedKeyFiles, err := filesInDir(filepath.Join(dataDir, "server"), "authorized_keys_*")
	if err != nil {
		return nil, err
	}
	for _, authorizedKeyFile := range alwaysAuthorizedKeyFiles {
		authorized[filepath.Base(authorizedKeyFile)] = struct{}{}
	}
	authorizedKeyFiles, err := filesInDir(filepath.Join(dataDir, "upstreams", upstream), "authorized_keys_*")
	if err != nil {
		return nil, err
	}
	for _, authorizedKeyFile := range authorizedKeyFiles {
		authorized[filepath.Base(authorizedKeyFile)] = struct{}{}
	}
	list := make([]string, 0, len(authorized))
	for authorized := range authorized {
		list = append(list, authorized)
	}
	sort.Strings(list)
	return list, nil
}
