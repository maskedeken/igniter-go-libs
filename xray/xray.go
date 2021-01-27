package xray

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/transport/internet"

	vlog "github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"

	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/xtls"

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
)

var (
	runningFlag atomic.Value
	v2Instance  *core.Instance
)

type XRayConfig struct {
	// SocksAddr socks5 proxy address
	SocksAddr string
	// SocksPort socks5 proxy port
	SocksPort int
	// ServerAddr trojan proxy address
	ServerAddr string
	// ServerPort trojan proxy port
	ServerPort int
	// SNI tls server name
	SNI string
	// Password trojan password
	Password string
	// AllowInsecure skip verify
	AllowInsecure bool
	// Flow tls flow control
	Flow string
}

func Start(config *XRayConfig) (err error) {
	v2Config, err := generateV2Config(config)
	if err != nil {
		return
	}

	v2Instance, err = core.New(v2Config)
	if err != nil {
		return
	}

	if err = v2Instance.Start(); err != nil {
		return
	}

	runningFlag.Store(true)
	return
}

func IsRunning() bool {
	run := runningFlag.Load()
	return run.(bool)
}

func Stop() (err error) {
	if IsRunning() && v2Instance != nil {
		err = v2Instance.Close()
	}

	runningFlag.Store(false)
	return
}

func generateV2Config(opt *XRayConfig) (config *core.Config, err error) {
	// handle user input
	if opt.SocksPort <= 0 {
		return nil, fmt.Errorf("socks5 port is invalid: %v", opt.SocksPort)
	}

	if len(opt.ServerAddr) <= 0 {
		return nil, fmt.Errorf("trojan host is empty: %v", opt.ServerAddr)
	}

	if opt.ServerPort == 0 {
		opt.ServerPort = 443
	}

	if opt.ServerPort <= 0 {
		return nil, fmt.Errorf("trojan port is invalid: %v", opt.ServerPort)
	}

	trojanAddress := v2net.ParseAddress(opt.ServerAddr)
	sni := opt.SNI
	if sni == "" && trojanAddress.Family().IsDomain() {
		sni = trojanAddress.Domain()
	}
	streamConfig, err := buildStreamConfig(sni, opt.Flow, opt.AllowInsecure)
	if err != nil {
		return nil, err
	}

	inboundProxy := serial.ToTypedMessage(&socks.ServerConfig{
		UdpEnabled: true,
		AuthType:   socks.AuthType_NO_AUTH,
	})
	receiverConfig := &proxyman.ReceiverConfig{
		PortRange: v2net.SinglePortRange(v2net.Port(opt.SocksPort)),
		Listen:    v2net.NewIPOrDomain(v2net.ParseAddress(opt.SocksAddr)),
	}
	if len(opt.SocksAddr) > 0 {
		receiverConfig.Listen = v2net.NewIPOrDomain(v2net.ParseAddress(opt.SocksAddr))
	}

	account := &trojan.Account{
		Password: opt.Password,
	}
	if strings.HasPrefix(opt.Flow, "xtls-rprx-") {
		account.Flow = opt.Flow
	}
	server := &protocol.ServerEndpoint{
		Address: v2net.NewIPOrDomain(trojanAddress),
		Port:    uint32(opt.ServerPort),
		User: []*protocol.User{{
			Account: serial.ToTypedMessage(account),
		}},
	}
	senderConfig := &proxyman.SenderConfig{
		StreamSettings: streamConfig,
	}
	outboundProxy := serial.ToTypedMessage(&trojan.ClientConfig{
		Server: []*protocol.ServerEndpoint{server},
	})

	config = &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			Tag:              "socks",
			ReceiverSettings: serial.ToTypedMessage(receiverConfig),
			ProxySettings:    inboundProxy,
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			Tag:            "proxy",
			SenderSettings: serial.ToTypedMessage(senderConfig),
			ProxySettings:  outboundProxy,
		}},
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&vlog.Config{
				ErrorLogLevel: clog.Severity_Warning,
				ErrorLogType:  vlog.LogType_Console,
				AccessLogType: vlog.LogType_Console,
			}),
		},
	}

	return
}

func buildTLSConfig(sni string, allowInsecure bool) (tlsConfig *tls.Config) {
	tlsConfig = &tls.Config{}
	if sni != "" {
		tlsConfig.ServerName = sni
	}

	tlsConfig.AllowInsecure = allowInsecure
	tlsConfig.NextProtocol = []string{"h2", "http/1.1"}
	return
}

func buildXTLSConfig(sni string, allowInsecure bool) (xtlsConfig *xtls.Config) {
	xtlsConfig = &xtls.Config{}
	if sni != "" {
		xtlsConfig.ServerName = sni
	}

	xtlsConfig.AllowInsecure = allowInsecure
	xtlsConfig.NextProtocol = []string{"h2", "http/1.1"}
	return
}

func buildStreamConfig(sni, flow string, allowInsecure bool) (streamConfig *internet.StreamConfig, err error) {
	switch flow {
	case "xtls-rprx-origin", "xtls-rprx-origin-udp443",
		"xtls-rprx-direct", "xtls-rprx-direct-udp443",
		"xtls-rprx-splice", "xtls-rprx-splice-udp443":
		xtlsConfig := buildXTLSConfig(sni, allowInsecure)
		streamConfig = &internet.StreamConfig{
			SecurityType:     serial.GetMessageType(xtlsConfig),
			SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(xtlsConfig)},
		}
	case "", "tls":
		tlsConfig := buildTLSConfig(sni, allowInsecure)
		streamConfig = &internet.StreamConfig{
			SecurityType:     serial.GetMessageType(tlsConfig),
			SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(tlsConfig)},
		}
	default:
		return nil, fmt.Errorf("invalid flow type: %s", flow)
	}

	return
}

func init() {
	// default value
	runningFlag.Store(false)
}
