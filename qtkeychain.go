package keyring

import (
	"os"
	"runtime"
)

// ReadPassword tries to read a password written by appName using qtkeychain.
func ReadPassword(appName, appDisplayName, key string) (string, error) {
	keyrings := []BackendType{}
	conf := Config{
		KWalletAppID: appDisplayName,
		AppName:      appName,
	}
	switch runtime.GOOS {
	case "windows":
		keyrings = []BackendType{WinCredBackend}
	case "darwin":
		keyrings = []BackendType{KeychainBackend}
	default:
		keyrings = []BackendType{SecretServiceBackend, KWalletBackend}
		if os.Getenv("XDG_CURRENT_DESKTOP") == "KDE" {
			keyrings[0], keyrings[1] = keyrings[1], keyrings[0]
		}
	}
	conf.AllowedBackends = keyrings
	k, err := Open(conf)
	if err != nil {
		return "", err
	}
	item, err := k.Get(key)
	return string(item.Data), err
}
