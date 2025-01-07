package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"wiretap/peer"
	"wiretap/transport/icmp"
	"wiretap/transport/tcp"
	"wiretap/transport/udp"
)

const USE_ENDPOINT_PORT = -1

var (
	Version            = "v0.0.0"
	Endpoint           = ""
	Port               = 51820
	Keepalive          = 25
	MTU                = 1420
	ShowHidden         = false
	ClientSubnet4 = netip.MustParsePrefix("172.16.0.0/16")
	ClientSubnet6 = netip.MustParsePrefix("fd:16::/40")
	Subnets4      = netip.MustParsePrefix("172.17.0.0/16")
	Subnets6      = netip.MustParsePrefix("fd:17::/40")
	SubnetV4Bits       = 24
	SubnetV6Bits       = 48
)

// check is a helper function that logs and exits if an error is not nil.
func check(message string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", message, err)
	}
}

type serveCmdConfig struct {
	configFile        string
	clientAddr4       string
	clientAddr6       string
	quiet             bool
	debug             bool
	simple            bool
	logging           bool
	logFile           string
	catchTimeout      uint
	connTimeout       uint
	keepaliveIdle     uint
	keepaliveCount    uint
	keepaliveInterval uint
	disableV6         bool
	localhostIP       string
}

type wiretapDefaultConfig struct {
	endpoint         string
	port             int
	allowedIPs       string
	serverAddr4      string
	serverAddr6      string
	keepalive        int
	mtu              int
}

// Defaults for serve command.
var serveCmd = serveCmdConfig{
	configFile:        "",
	clientAddr4:       ClientSubnet4.Addr().Next().Next().String(),
	clientAddr6:       ClientSubnet6.Addr().Next().Next().String(),
	quiet:             false,
	debug:             false,
	simple:            false,
	logging:           false,
	logFile:           "wiretap.log",
	catchTimeout:      5 * 1000,
	connTimeout:       5 * 1000,
	keepaliveIdle:     60,
	keepaliveCount:    3,
	keepaliveInterval: 60,
	disableV6:         false,
	localhostIP:       "",
}

var wiretapDefault = wiretapDefaultConfig{
	endpoint:         Endpoint,
	port:             Port,
	allowedIPs:       fmt.Sprintf("%s,%s", ClientSubnet4.Addr().Next().String()+"/32", ClientSubnet6.Addr().Next().String()+"/128"),
	serverAddr4:      Subnets4.Addr().Next().Next().String(),
	serverAddr6:      Subnets6.Addr().Next().Next().String(),
	keepalive:        Keepalive,
	mtu:              MTU,
}

// Run parses/processes/validates args and then connects to peer,
// proxying traffic from peer into local network.
func (c serveCmdConfig) Run() {
	// Read config from file and/or environment.
	viper.AutomaticEnv()
	viper.SetEnvPrefix("WIRETAP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if c.configFile != "" {
		viper.SetConfigType("ini")
		viper.SetConfigFile(c.configFile)
		if err := viper.ReadInConfig(); err != nil {
			check("error reading config file", err)
		}
	}

	// Synchronization vars.
	var (
		wg   sync.WaitGroup
		lock sync.Mutex
	)

	// Configure logging.
	log.SetOutput(os.Stdout)
	log.SetPrefix("WIRETAP: ")
	if c.quiet {
		log.SetOutput(io.Discard)
	}
	if c.logging {
		f, err := os.OpenFile(c.logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		check("error opening log file", err)
		defer f.Close()

		if c.quiet {
			log.SetOutput(f)
		} else {
			log.SetOutput(io.MultiWriter(os.Stdout, f))
		}
	}

	// Check for required flags.
	if !viper.IsSet("Peer.publickey") {
		check("config error", errors.New("public key of peer is required"))
	}

	Addresses := []string{viper.GetString("Interface.ipv4") + "/32"}
	if !viper.IsSet("disableipv6") {
		Addresses = append(Addresses, viper.GetString("Interface.ipv6")+"/128")
	}
	aips := []string{}
	for _, ip := range strings.Split(viper.GetString("Peer.allowed"), ",") {
		if viper.IsSet("disableipv6") && netip.MustParsePrefix(ip).Addr().Is6() {
			continue
		}

		aips = append(aips, ip)
	}
	configArgs := peer.ConfigArgs{
		PrivateKey: viper.GetString("Interface.privatekey"),
		ListenPort: viper.GetInt("Interface.port"),
		Peers: []peer.PeerConfigArgs{
			{
				PublicKey: viper.GetString("Peer.publickey"),
				Endpoint:  viper.GetString("Peer.endpoint"),
				PersistentKeepaliveInterval: func() int {
					if len(viper.GetString("Peer.endpoint")) > 0 {
						return viper.GetInt("Peer.keepalive")
					} else {
						return 0
					}
				}(),
				AllowedIPs: aips,
			},
		},
		Addresses: Addresses,
		LocalhostIP: viper.GetString("Interface.LocalhostIP"),
	}

	config, err := peer.GetConfig(configArgs)
	check("failed to make configuration", err)

	// Print public key for easier configuration.
	fmt.Println()
	fmt.Println("Configuration:")
	fmt.Println(strings.Repeat("-", 32))
	fmt.Print(config.AsShareableFile())
	fmt.Println(strings.Repeat("-", 32))
	fmt.Println()

	// Create virtual interface with this address and MTU.
	ipv4Addr, err := netip.ParseAddr(viper.GetString("Interface.ipv4"))
	check("failed to parse ipv4 address", err)

	Addrs := []netip.Addr{ipv4Addr}

	if !viper.IsSet("disableipv6") {
		ipv6Addr, err := netip.ParseAddr(viper.GetString("Interface.ipv6"))
		check("failed to parse ipv6 address", err)
		Addrs = append(Addrs, ipv6Addr)
	}

	tun, tnet, err := netstack.CreateNetTUN(
		Addrs,
		[]netip.Addr{},
		viper.GetInt("Interface.mtu"),
	)
	check("failed to create TUN", err)

	transportHandler := func() *netstack.Net {
		return tnet
	}()

	var logger int
	if c.debug {
		logger = device.LogLevelVerbose
	} else if c.quiet {
		logger = device.LogLevelSilent
	} else {
		logger = device.LogLevelError
	}

	s := transportHandler.Stack()
	s.SetPromiscuousMode(1, true)

	// TCP Forwarding mechanism.
	tcpConfig := tcp.Config{
		CatchTimeout:      time.Duration(c.catchTimeout) * time.Millisecond,
		ConnTimeout:       time.Duration(c.connTimeout) * time.Millisecond,
		KeepaliveIdle:     time.Duration(c.keepaliveIdle) * time.Second,
		KeepaliveInterval: time.Duration(c.keepaliveInterval) * time.Second,
		KeepaliveCount:    int(c.keepaliveCount),
		Tnet:              transportHandler,
		StackLock:         &lock,
	}
	tcpForwarder := gtcp.NewForwarder(s, 0, 65535, tcp.Handler(tcpConfig))
	s.SetTransportProtocolHandler(gtcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// UDP Forwarding mechanism.
	udpConfig := udp.Config{
		Tnet:      transportHandler,
		StackLock: &lock,
	}
	s.SetTransportProtocolHandler(gudp.ProtocolNumber, udp.Handler(udpConfig))

	// Setup localhost forwarding IP using IPTables
	if viper.IsSet("Interface.LocalhostIP") && viper.GetString("Interface.LocalhostIP") != "" {
		localhostAddr, err := netip.ParseAddr(viper.GetString("Interface.LocalhostIP"))
		check("failed to parse localhost-ip address", err)
		if len(localhostAddr.AsSlice()) != 4 {
			log.Fatalf("Localhost IP must be an IPv4 address")
		}

		configureLocalhostForwarding(localhostAddr, s)

		if localhostAddr.IsLoopback() {
			fmt.Printf("=== WARNING: %s is a loopback IP. It will probably not work for Localhost Forwarding ===\n", localhostAddr.String())

		} else if localhostAddr.IsMulticast() {
			fmt.Printf("=== WARNING: %s is a Multicast IP. Your OS might still send extra packets to other IPs when you target this IP ===\n", localhostAddr.String())

		} else if !localhostAddr.IsPrivate() {
			fmt.Printf("=== WARNING: %s is a public IP. If Localhost Forwarding fails, your traffic may actually touch that IP ===\n", localhostAddr.String())
		}

		fmt.Println("Localhost Forwarding configured for ", localhostAddr)
		fmt.Println()
	}

	// Make new device.
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logger, ""))
	// Configure wireguard.
	fmt.Println(config.AsIPC())
	err = dev.IpcSet(config.AsIPC())
	check("failed to configure wireguard device", err)
	err = dev.Up()
	check("failed to bring up device", err)

	// Start ICMP Handler.
	wg.Add(1)
	go func() {
		icmp.Handle(transportHandler, &lock)
		wg.Done()
	}()

	wg.Add(1)
	wg.Wait()
}

// Setup iptables rule for localhost re-routing (DNAT)
func configureLocalhostForwarding(localhostAddr netip.Addr, s *stack.Stack) {
	// https://pkg.go.dev/gvisor.dev/gvisor@v0.0.0-20231115214215-71bcc96c6e38/pkg/tcpip/stack
	newFilter := stack.EmptyFilter4()
	newFilter.Dst = tcpip.AddrFromSlice(localhostAddr.AsSlice())
	newFilter.DstMask = tcpip.AddrFromSlice([]byte{255, 255, 255, 255})

	newRule := new(stack.Rule)
	newRule.Filter = newFilter

	//Do address-only DNAT; port remains the same, so all ports are effectively forwarded to localhost
	newRule.Target = &stack.DNATTarget{
		Addr:            tcpip.AddrFromSlice([]byte{127, 0, 0, 1}),
		NetworkProtocol: ipv4.ProtocolNumber,
		ChangeAddress:   true,
		ChangePort:      false,
	}

	ipt := s.IPTables()
	natTable := ipt.GetTable(stack.NATID, false)
	newTable := prependIPtableRule(natTable, *newRule, stack.Prerouting)

	//ForceReplaceTable ensures IPtables get enabled; ReplaceTable doesn't.
	ipt.ForceReplaceTable(stack.NATID, newTable, false)
}

// Adds a rule to the start of a table chain.
func prependIPtableRule(table stack.Table, newRule stack.Rule, chain stack.Hook) (stack.Table) {
	insertIndex := int(table.BuiltinChains[chain])
	table.Rules = slices.Insert(table.Rules, insertIndex, newRule)

	// Increment the later chain and underflow index pointers to account for the rule added to the Rules slice
	// https://pkg.go.dev/gvisor.dev/gvisor@v0.0.0-20231115214215-71bcc96c6e38/pkg/tcpip/stack#Table
	for chainHook, ruleIndex := range table.BuiltinChains {
		//assumes each chain has its own unique starting rule index
		if ruleIndex > insertIndex {
			table.BuiltinChains[chainHook] = ruleIndex + 1
		}
	}
	for chainHook, ruleIndex := range table.Underflows {
		if ruleIndex >= insertIndex {
			table.Underflows[chainHook] = ruleIndex + 1
		}
	}
	return table
}

func main() {
	var err error

	rootCmd := &cobra.Command{
		Use: os.Args[0],
		//Short: "wiretap-lite",
		//Long:  `Listen and proxy traffic into target network`,
		Run: func(cmd *cobra.Command, args []string) {
			serveCmd.Run()
		},
	}

	// Flags.
	rootCmd.Flags().StringVarP(&serveCmd.configFile, "config-file", "f", serveCmd.configFile, "wireguard config file to read from")
	rootCmd.Flags().IntP("port", "p", wiretapDefault.port, "listener port to use for connections")
	rootCmd.Flags().BoolVarP(&serveCmd.quiet, "quiet", "q", serveCmd.quiet, "silence wiretap log messages")
	rootCmd.Flags().BoolVarP(&serveCmd.debug, "debug", "d", serveCmd.debug, "enable wireguard log messages")
	rootCmd.Flags().BoolVarP(&serveCmd.simple, "simple", "", serveCmd.simple, "disable multihop and multiclient features for a simpler setup")
	rootCmd.Flags().BoolVarP(&serveCmd.disableV6, "disable-ipv6", "", serveCmd.disableV6, "disable ipv6")
	rootCmd.Flags().BoolVarP(&serveCmd.logging, "log", "l", serveCmd.logging, "enable logging to file")
	rootCmd.Flags().StringVarP(&serveCmd.logFile, "log-file", "o", serveCmd.logFile, "write log to this filename")
	rootCmd.Flags().StringVarP(&serveCmd.localhostIP, "localhost-ip", "i", serveCmd.localhostIP, "[EXPERIMENTAL] redirect Wiretap packets destined for this IPv4 address to server's localhost")
	rootCmd.Flags().IntP("keepalive", "k", wiretapDefault.keepalive, "tunnel keepalive in seconds")
	rootCmd.Flags().IntP("mtu", "m", wiretapDefault.mtu, "tunnel MTU")
	rootCmd.Flags().UintVarP(&serveCmd.catchTimeout, "completion-timeout", "", serveCmd.catchTimeout, "time in ms for client to complete TCP connection to server")
	rootCmd.Flags().UintVarP(&serveCmd.connTimeout, "conn-timeout", "", serveCmd.connTimeout, "time in ms for server to wait for outgoing TCP handshakes to complete")
	rootCmd.Flags().UintVarP(&serveCmd.keepaliveIdle, "keepalive-idle", "", serveCmd.keepaliveIdle, "time in seconds before TCP keepalives are sent to client")
	rootCmd.Flags().UintVarP(&serveCmd.keepaliveInterval, "keepalive-interval", "", serveCmd.keepaliveInterval, "time in seconds between TCP keepalives")
	rootCmd.Flags().UintVarP(&serveCmd.keepaliveCount, "keepalive-count", "", serveCmd.keepaliveCount, "number of unacknowledged TCP keepalives before closing connection")

	rootCmd.Flags().StringVarP(&serveCmd.clientAddr4, "ipv4-client", "", serveCmd.clientAddr4, "ipv4 address of client")
	rootCmd.Flags().StringVarP(&serveCmd.clientAddr6, "ipv6-client", "", serveCmd.clientAddr6, "ipv6 address of client")

	// Bind supported flags to environment variables.
	err = viper.BindPFlag("simple", rootCmd.Flags().Lookup("simple"))
	check("error binding flag to viper", err)

	err = viper.BindPFlag("disableipv6", rootCmd.Flags().Lookup("disable-ipv6"))
	check("error binding flag to viper", err)

	err = viper.BindPFlag("Interface.LocalhostIP", rootCmd.Flags().Lookup("localhost-ip"))
	check("error binding flag to viper", err)

	// Quiet and debug flags must be used independently.
	rootCmd.MarkFlagsMutuallyExclusive("debug", "quiet")

	// Deprecated flags, kept for backwards compatibility.
	rootCmd.Flags().StringP("private", "", "", "wireguard private key for interface")
	rootCmd.Flags().StringP("public", "", "", "wireguard public key of remote peer for interface")
	rootCmd.Flags().StringP("endpoint", "", wiretapDefault.endpoint, "socket address of remote peer that server will connect to (example \"1.2.3.4:51820\")")
	rootCmd.Flags().StringP("allowed", "a", wiretapDefault.allowedIPs, "comma-separated list of CIDR IP ranges to associate with peer")
	rootCmd.Flags().StringP("ipv4", "", wiretapDefault.serverAddr4, "ipv4 address")
	rootCmd.Flags().StringP("ipv6", "", wiretapDefault.serverAddr6, "ipv6 address")

	// Bind deprecated flags to viper.
	err = viper.BindPFlag("Interface.privatekey", rootCmd.Flags().Lookup("private"))
	check("error binding flag to viper", err)
	err = viper.BindPFlag("Interface.port", rootCmd.Flags().Lookup("port"))
	check("error binding flag to viper", err)
	err = viper.BindPFlag("Interface.ipv4", rootCmd.Flags().Lookup("ipv4"))
	check("error binding flag to viper", err)
	err = viper.BindPFlag("Interface.ipv6", rootCmd.Flags().Lookup("ipv6"))
	check("error binding flag to viper", err)
	err = viper.BindPFlag("Interface.mtu", rootCmd.Flags().Lookup("mtu"))
	check("error binding flag to viper", err)

	err = viper.BindPFlag("Peer.publickey", rootCmd.Flags().Lookup("public"))
	check("error binding flag to viper", err)
	err = viper.BindPFlag("Peer.endpoint", rootCmd.Flags().Lookup("endpoint"))
	check("error binding flag to viper", err)
	err = viper.BindPFlag("Peer.allowed", rootCmd.Flags().Lookup("allowed"))
	check("error binding flag to viper", err)
	err = viper.BindPFlag("Peer.keepalive", rootCmd.Flags().Lookup("keepalive"))
	check("error binding flag to viper", err)

	// Set default values for viper.
	viper.SetDefault("Interface.port", wiretapDefault.port)
	viper.SetDefault("Interface.ipv4", wiretapDefault.serverAddr4)
	viper.SetDefault("Interface.ipv6", wiretapDefault.serverAddr6)
	viper.SetDefault("Interface.mtu", wiretapDefault.mtu)

	viper.SetDefault("Interface.Peer.endpoint", wiretapDefault.endpoint)
	viper.SetDefault("Interface.Peer.allowed", wiretapDefault.allowedIPs)
	viper.SetDefault("Interface.Peer.keepalive", wiretapDefault.keepalive)

	rootCmd.Flags().SortFlags = false

	err = rootCmd.Execute()
	if err != nil {
		fmt.Printf("Command execution failed: %v\n", err)
	}
}
