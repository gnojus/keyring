package keyring

import (
	"os"
	"runtime"
)

// ReadPassword tries to read a password written by appName using qtkeychain.
func ReadPassword(appName, appDisplayName, key string) (string, error) {
	keyrings := []BackendType{}
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
	k, err := Open(Config{
		AllowedBackends: keyrings,

		KWalletAppID: appDisplayName,

		KWalletFolder:           appName,
		KeychainName:            appName,
		WinCredPrefix:           appName,
		LibSecretCollectionName: appName,
	})
	if err != nil {
		return "", err
	}
	item, err := k.Get(key)
	return string(item.Data), err
}
