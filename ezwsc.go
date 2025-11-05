package ezwsc

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/crypto4people/zoro/singbox"

	libbox "github.com/sagernet/sing-box/experimental/libbox"
)

var (
	mu  sync.Mutex
	svc *libbox.BoxService
)

func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()

	return svc != nil
}

func parseKey(privateKeyHex string) (*ecdsa.PrivateKey, error) {
	hex := strings.TrimPrefix(strings.TrimSpace(privateKeyHex), "0x")
	return crypto.HexToECDSA(hex)
}

func StartWithTunFD(ctx context.Context, fd int, server string, privateKeyHex string) error {
	mu.Lock()
	defer mu.Unlock()

	if svc != nil {
		return errors.New("vpn already running")
	}
	if fd < 0 {
		return errors.New("invalid TUN fd")
	}

	priv, err := parseKey(privateKeyHex)
	if err != nil {
		return err
	}

	tunCIDR := "10.66.0.1/24"
	sbConfig, err := singbox.New(server, priv, singbox.Settings{
		TunAddr: &tunCIDR,
		WSCPath: "/wsc",
		UseTLS:  false,
	}, singbox.ModeTun)
	if err != nil {
		return err
	}

	confJSON, err := sbConfig.JSON()
	if err != nil {
		return err
	}

	plat := &platform{fd: int32(fd)}
	svc, err = libbox.NewService(string(confJSON), plat)
	if err != nil {
		return err
	}

	if err := svc.Start(); err != nil {
		_ = svc.Close()
		return err
	}

	if ctx != nil {
		go func() { <-ctx.Done(); _ = Stop() }()
	}

	return nil
}

func Stop() error {
	mu.Lock()
	defer mu.Unlock()

	if svc == nil {
		return nil
	}
	err := svc.Close()
	svc = nil
	return err
}
