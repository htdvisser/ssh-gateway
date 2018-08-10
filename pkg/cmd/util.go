package cmd

import (
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

func getPublicKey(perms *ssh.Permissions) ssh.PublicKey {
	bytes, err := base64.RawStdEncoding.DecodeString(perms.Extensions["pubkey"])
	if err != nil {
		return nil
	}
	pubKey, err := ssh.ParsePublicKey(bytes)
	if err != nil {
		return nil
	}
	return pubKey
}
