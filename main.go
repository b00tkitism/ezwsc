package ezwsc

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/crypto4people/zoro/singbox"
	"github.com/ethereum/go-ethereum/crypto"
	box "github.com/sagernet/sing-box"
)

var (
	mu          sync.Mutex
	boxInstance *box.Box
)

func Start(ctx context.Context, server string, privateKeyHex string) error {
	mu.Lock()
	defer mu.Unlock()

	if boxInstance != nil {
		return errors.New("vpn already running")
	}

	hex := strings.TrimPrefix(strings.TrimSpace(privateKeyHex), "0x")
	priv, err := crypto.HexToECDSA(hex)
	if err != nil {
		return err
	}

	tunCIDR := "10.66.0.1/24"

	sb, err := singbox.Config(ctx, server, priv, &singbox.Settings{
		TunAddr: &tunCIDR,
	}, singbox.ModeTun)
	if err != nil {
		return err
	}

	if err := sb.Start(); err != nil {
		return err
	}

	boxInstance = sb

	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = Stop()
		}()
	}

	return nil
}

func Stop() error {
	mu.Lock()
	defer mu.Unlock()

	if boxInstance == nil {
		return nil
	}
	err := boxInstance.Close()
	boxInstance = nil
	return err
}

func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()

	return boxInstance != nil
}
