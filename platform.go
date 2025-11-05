package ezwsc

import (
	"fmt"

	"github.com/sagernet/sing-box/experimental/libbox"
)

var _ libbox.PlatformInterface = (*platform)(nil)

type platform struct {
	fd int32
}

func (plat *platform) ClearDNSCache() {}

func (plat *platform) CloseDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}

func (plat *platform) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return nil, nil
}

func (plat *platform) IncludeAllNetworks() bool {
	return true
}

func (plat *platform) LocalDNSTransport() libbox.LocalDNSTransport {
	return nil
}

func (plat *platform) PackageNameByUid(uid int32) (string, error) {
	return "", nil
}

func (plat *platform) ReadWIFIState() *libbox.WIFIState {
	return nil
}

func (plat *platform) SendNotification(notification *libbox.Notification) error {
	return nil
}

func (plat *platform) StartDefaultInterfaceMonitor(listener libbox.InterfaceUpdateListener) error {
	return nil
}

func (plat *platform) SystemCertificates() libbox.StringIterator {
	return nil
}

func (plat *platform) UIDByPackageName(packageName string) (int32, error) {
	return 0, nil
}

func (plat *platform) UnderNetworkExtension() bool {
	return false
}

func (plat *platform) UsePlatformAutoDetectInterfaceControl() bool {
	return false
}

func (plat *platform) AutoDetectInterfaceControl(_ int32) error {
	return nil
}

func (plat *platform) OpenTun(_ libbox.TunOptions) (int32, error) {
	return plat.fd, nil
}

func (plat *platform) WriteLog(message string) {
	fmt.Println("[singbox]", message)
}

func (plat *platform) UseProcFS() bool {
	return false
}

func (plat *platform) FindConnectionOwner(_ int32, _ string, _ int32, _ string, _ int32) (int32, error) {
	return 0, nil
}
