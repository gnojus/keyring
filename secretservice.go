//go:build linux
// +build linux

package keyring

import (
	"encoding/hex"
	"errors"
	"fmt"

	"strings"

	"github.com/godbus/dbus/v5"
	dbkeyring "github.com/ppacher/go-dbus-keyring"
)

func init() {
	// silently fail if dbus isn't available
	bus, err := dbus.SessionBus()
	if err != nil {
		return
	}

	supportedBackends[SecretServiceBackend] = opener(func(cfg Config) (Keyring, error) {
		service, err := dbkeyring.GetSecretService(bus)
		ring := &secretsKeyring{
			name: cfg.AppName,
		}
		if err != nil {
			return ring, err
		}
		ring.service = service
		ring.session, err = service.OpenSession()
		return ring, err
	})
}

type secretsKeyring struct {
	name    string
	session dbkeyring.Session
	service dbkeyring.SecretService
}

var errCollectionNotFound = errors.New("The collection does not exist. Please add a key first")

func decodeKeyringString(src string) string {
	var dst strings.Builder
	for i := 0; i < len(src); i++ {
		if src[i] != '_' {
			dst.WriteString(string(src[i]))
		} else {
			if i+3 > len(src) {
				return src
			}
			hexstring := src[i+1 : i+3]
			decoded, err := hex.DecodeString(hexstring)
			if err != nil {
				return src
			}
			dst.Write(decoded)
			i += 2
		}
	}
	return dst.String()
}

func (k *secretsKeyring) Get(key string) (Item, error) {
	ul, lo, err := k.service.SearchItems(map[string]string{
		"server": k.name,
		"user":   key,
	})
	if Debug {
		c, err := k.service.GetAllCollections()
		labels := []string{}
		if err == nil {
			for _, c := range c {
				l, _ := c.GetLabel()
				labels = append(labels, l)
			}
			debugf("collections: %q", labels)
		}
	}
	if err != nil {
		return Item{}, fmt.Errorf("libsecret: searching failed: %w", err)
	}
	items := append(ul, lo...)
	if len(items) != 1 {
		return Item{}, fmt.Errorf("libsecret: found %d items instead of 1", len(items))
	}

	if len(ul) == 0 {
		_, err = items[0].Unlock()
		if err != nil {
			return Item{}, fmt.Errorf("libsecret: unlocking item: %w", err)
		}
	}

	secret, err := items[0].GetSecret(k.session.Path())
	if err != nil {
		return Item{}, fmt.Errorf("libsecret: getting secret: %w", err)
	}
	return Item{
		Key:  key,
		Data: secret.Value,
	}, nil
}

// GetMetadata for libsecret returns an error indicating that it's unsupported
// for this backend.
//
// libsecret actually implements a metadata system which we could use, "Secret
// Attributes"; I found no indication in documentation of anything like an
// automatically maintained last-modification timestamp, so to use this we'd
// need to have a SetMetadata API too.  Which we're not yet doing, but feel
// free to contribute patches.
func (k *secretsKeyring) GetMetadata(key string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

func (k *secretsKeyring) Set(item Item) error {
	panic("not implemented")
}

func (k *secretsKeyring) Remove(key string) error {
	panic("not implemented")
}

func (k *secretsKeyring) Keys() ([]string, error) {
	panic("not implemented")
}
