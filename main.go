package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"masque-plus/internal/httpcheck"
	"masque-plus/internal/logutil"
	"masque-plus/internal/scanner"
)

var (
	defaultV4 = []string{
		"162.159.198.1:443",
		"162.159.198.2:443",
	}
	defaultV6 = []string{
		"2606:4700:103::1",
		"2606:4700:103::2",
	}
	defaultRange4         = []string{
		"162.159.192.0/24",
		"162.159.197.0/24",
		"162.159.198.0/24",
	}
	defaultRange6         = []string{
		"2606:4700:103::/64",
	}
	defaultBind           = "127.0.0.1:1080"
	defaultConfigFile     = "./config.json"
	defaultUsquePath      = "./usque"
	defaultConnectTimeout = 15 * time.Minute
	defaultTestURL        = "https://connectivity.cloudflareclient.com/cdn-cgi/trace"
	defaultSNI            = "consumer-masque.cloudflareclient.com"
)

var (
	connectPort       = 443
	dnsStr            string
	dnsTimeout        = 2 * time.Second
	initialPacketSize = 1242
	keepalivePeriod   = 30 * time.Second
	localDns          bool
	mtu               = 1280
	noTunnelIpv4      bool
	noTunnelIpv6      bool
	password          string
	username          string
	reconnectDelay    = 1 * time.Second
	sni               = defaultSNI
	useIpv6           bool
)

func main() {
	endpoint := flag.String("endpoint", "", "Endpoint to connect (IPv4, IPv6, domain; host or host:Port; for IPv6 with port use [IPv6]:Port)")
	bind := flag.String("bind", defaultBind, "IP:Port to bind SOCKS proxy")
	renew := flag.Bool("renew", false, "Force renewal of config even if config.json exists")
	scan := flag.Bool("scan", false, "Scan/auto-select a default endpoint")
	v4Flag := flag.Bool("4", false, "Force IPv4 endpoint list with --scan")
	v6Flag := flag.Bool("6", false, "Force IPv6 endpoint list with --scan")
	connectTimeout := flag.Duration("connect-timeout", defaultConnectTimeout, "Overall timeout for the final connect/process to be up")
	range4 := flag.String("range4", "", "comma-separated IPv4 CIDRs to scan")
	range6 := flag.String("range6", "", "comma-separated IPv6 CIDRs to scan")
	pingFlag := flag.Bool("ping", true, "Ping each candidate before connect")
	rtt := flag.Bool("rtt", false, "placeholder flag, not used")
	reserved := flag.String("reserved", "", "placeholder flag, not used")
	scanPerIP := flag.Duration("scan-timeout", 5*time.Second, "Per-endpoint scan timeout (dial+handshake)")
	scanMax := flag.Int("scan-max", 30, "Maximum number of endpoints to try during scan")
	scanVerboseChild := flag.Bool("scan-verbose-child", false, "Print MASQUE child process logs during scan")
	scanTunnelFailLimit := flag.Int("scan-tunnel-fail-limit", 2, "Number of 'Failed to connect tunnel' occurrences before skipping an endpoint")
	scanOrdered := flag.Bool("scan-ordered", false, "Scan candidates in CIDR order (disable shuffling)")
	testURL := flag.String("test-url", defaultTestURL, "URL used to verify connectivity over the SOCKS tunnel")

	// usque-specific flags
	flag.IntVar(&connectPort, "connect-port", connectPort, "Used port for MASQUE connection")
	flag.StringVar(&dnsStr, "dns", dnsStr, "comma-separated DNS servers to use")
	flag.DurationVar(&dnsTimeout, "dns-timeout", dnsTimeout, "Timeout for DNS queries")
	flag.IntVar(&initialPacketSize, "initial-packet-size", initialPacketSize, "Initial packet size for MASQUE connection")
	flag.DurationVar(&keepalivePeriod, "keepalive-period", keepalivePeriod, "Keepalive period for MASQUE connection")
	flag.BoolVar(&localDns, "local-dns", localDns, "Don't use the tunnel for DNS queries")
	flag.IntVar(&mtu, "mtu", mtu, "MTU for MASQUE connection")
	flag.BoolVar(&noTunnelIpv4, "no-tunnel-ipv4", noTunnelIpv4, "Disable IPv4 inside the MASQUE tunnel")
	flag.BoolVar(&noTunnelIpv6, "no-tunnel-ipv6", noTunnelIpv6, "Disable IPv6 inside the MASQUE tunnel")
	flag.StringVar(&password, "password", password, "Password for proxy authentication")
	flag.StringVar(&username, "username", username, "Username for proxy authentication")
	flag.DurationVar(&reconnectDelay, "reconnect-delay", reconnectDelay, "Delay between reconnect attempts")
	flag.StringVar(&sni, "sni", sni, "SNI address to use for MASQUE connection")
	flag.BoolVar(&useIpv6, "ipv6", useIpv6, "Use IPv6 for MASQUE connection")

	flag.Parse()

	_ = rtt
	_ = reserved
	_ = testURL

	if *v4Flag && *v6Flag {
		logErrorAndExit("both -4 and -6 provided")
	}
	if *endpoint == "" && !*scan {
		logErrorAndExit("--endpoint is required")
	}

	configFile := defaultConfigFile
	usquePath := defaultUsquePath

	logInfo("running in masque mode", nil)

	if *scan {
		logInfo("scanner mode enabled", nil)
		candidates := buildCandidatesFromFlags(*v6Flag, *v4Flag, *range4, *range6)

		if len(candidates) > 1 && !*scanOrdered {
			mrand.Seed(time.Now().UnixNano())
			mrand.Shuffle(len(candidates), func(i, j int) {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			})
		}

		if len(candidates) == 0 {
			chosen, err := pickDefaultEndpoint(*v6Flag)
			if err != nil {
				logErrorAndExit(err.Error())
			}
			*endpoint = chosen
		} else {
			bindIP, bindPort := mustSplitBind(*bind)

			startFn := func(ep string) (func(), bool, error) {
				cmdCfg := make(map[string]interface{})
				if data, err := os.ReadFile(configFile); err == nil {
					_ = json.Unmarshal(data, &cmdCfg)
				}
				addEndpointToConfig(cmdCfg, ep)
				if err := writeConfig(configFile, cmdCfg); err != nil {
					return nil, false, err
				}

				host, port, _ := parseEndpoint(ep)
				localPort := 443
				if port != "" {
					localPort, _ = strconv.Atoi(port)
				}
				ip := net.ParseIP(host)
				localIpv6 := ip != nil && ip.To4() == nil

				logConfig(ep, bindIP, bindPort)
				cmd := createUsqueCmd(usquePath, configFile, bindIP, bindPort, localPort, localIpv6)
				stdout, _ := cmd.StdoutPipe()
				stderr, _ := cmd.StderrPipe()

				if err := cmd.Start(); err != nil {
					return nil, false, err
				}

				st := &procState{}
				go handleScanner(bufio.NewScanner(stdout), bindIP+":"+bindPort, st, cmd, *scanVerboseChild, *scanTunnelFailLimit)
				go handleScanner(bufio.NewScanner(stderr), bindIP+":"+bindPort, st, cmd, *scanVerboseChild, *scanTunnelFailLimit)

				deadline := time.Now().Add(*scanPerIP)
				for time.Now().Before(deadline) {
					st.mu.Lock()
					ok := st.connected
					hsFail := st.handshakeFail
					st.mu.Unlock()

					if ok {
						break
					}
					if hsFail {
						stop := func() { _ = cmd.Process.Kill() }
						return stop, false, fmt.Errorf("handshake failure")
					}
					time.Sleep(120 * time.Millisecond)
				}

				st.mu.Lock()
				ok := st.connected
				st.mu.Unlock()

				stop := func() { _ = cmd.Process.Kill() }

				if ok {
					wcTimeout := *scanPerIP
					if wcTimeout <= 0 || wcTimeout > 5*time.Second {
						wcTimeout = 5 * time.Second
					}

					bindAddr := fmt.Sprintf("%s:%s", bindIP, bindPort)
					status, err := httpcheck.CheckWarpOverSocks(bindAddr, *testURL, wcTimeout)
					fields := map[string]string{
						"endpoint": ep,
						"bind":     bindAddr,
						"status":   string(status),
						"url":      *testURL,
						"timeout":  wcTimeout.String(),
					}
					if err != nil {
						fields["error"] = err.Error()
						logutil.Warn("warp check result", fields)
					} else {
						logutil.Info("warp check result", fields)
					}
				}

				return stop, ok, nil
			}

			chosen, err := scanner.TryCandidates(
				candidates,
				*scanMax,
				*pingFlag,
				3*time.Second,
				*scanPerIP,
				startFn,
			)
			if err != nil {
				logErrorAndExit(err.Error())
			}
			*endpoint = chosen
		}
	} else {
		host, port, err := parseEndpoint(*endpoint)
		if err != nil {
			logErrorAndExit(fmt.Sprintf("invalid endpoint: %v", err))
		}
		ip := net.ParseIP(host)
		if ip != nil {
			isV6 := ip.To4() == nil
			if useIpv6 != isV6 {
				logInfo(fmt.Sprintf("warning: endpoint is IPv%d but --ipv6=%v; overriding to match endpoint", map[bool]int{true: 6, false: 4}[isV6], useIpv6), nil)
				useIpv6 = isV6
			}
		} else if sni == defaultSNI {
			sni = host
		}
		if port != "" {
			p, err := strconv.Atoi(port)
			if err == nil {
				connectPort = p
			}
		}
	}

	bindIP, bindPort := mustSplitBind(*bind)

	if needRegister(configFile, *renew) {
		if err := runRegister(usquePath); err != nil {
			logErrorAndExit(fmt.Sprintf("failed to register: %v", err))
		}
	}
	logInfo("successfully loaded masque identity", nil)

	cfg := make(map[string]interface{})
	if data, err := os.ReadFile(configFile); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}

	addEndpointToConfig(cfg, *endpoint)

	if err := writeConfig(configFile, cfg); err != nil {
		logErrorAndExit(fmt.Sprintf("failed to write config: %v", err))
	}

	logConfig(*endpoint, bindIP, bindPort)
	if err := runSocks(usquePath, configFile, bindIP, bindPort, *connectTimeout); err != nil {
		logErrorAndExit(fmt.Sprintf("SOCKS start failed: %v", err))
	}
}

// ------------------------ Helpers ------------------------

func buildCandidatesFromFlags(v6, v4 bool, r4csv, r6csv string) []string {
	ports := []string{
		"443",
		//"500",
		//"1701",
		//"4500",
		//"4443",
		//"8443",
		//"8095",
	}

	var r4, r6 []string
	if strings.TrimSpace(r4csv) != "" {
		r4 = splitCSV(r4csv)
	} else {
		r4 = append([]string{}, defaultRange4...)
	}
	if strings.TrimSpace(r6csv) != "" {
		r6 = splitCSV(r6csv)
	} else {
		r6 = append([]string{}, defaultRange6...)
	}

	ver := scanner.Any
	if v6 {
		ver = scanner.V6
	} else if v4 {
		ver = scanner.V4
	}

	cands, err := scanner.BuildCandidates(ver, r4, r6, ports)
	if err != nil {
		logInfo(fmt.Sprintf("scanner.BuildCandidates error: %v", err), nil)
		return nil
	}
	return cands
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func pickDefaultEndpoint(v6 bool) (string, error) {
	pool := defaultV4
	if v6 {
		pool = defaultV6
	}
	if len(pool) == 0 {
		return "", fmt.Errorf("no default endpoints available")
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	return pool[nBig.Int64()], nil
}

func splitBind(b string) (string, string, error) {
	parts := strings.Split(b, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("--bind must be in format IP:Port")
	}
	if err := validatePort(parts[1]); err != nil {
		return "", "", err
	}
	return parts[0], parts[1], nil
}

func mustSplitBind(b string) (string, string) {
	bindIP, bindPort, err := splitBind(b)
	if err != nil {
		logErrorAndExit(err.Error())
	}
	return bindIP, bindPort
}

func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", p)
	}
	return nil
}

func writeConfig(path string, cfg map[string]interface{}) error {
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(path, data, 0644)
}

func logConfig(endpoint, bindIP, bindPort string) {
	fields := map[string]string{
		"endpoint":     endpoint,
		"bind":         fmt.Sprintf("%s:%s", bindIP, bindPort),
		"sni":          sni,
		"connect-port": strconv.Itoa(connectPort),
		"ipv6":         strconv.FormatBool(useIpv6),
		"dns":          dnsStr,
		"dns-timeout":  dnsTimeout.String(),
		"mtu":          strconv.Itoa(mtu),
		"keepalive":    keepalivePeriod.String(),
	}
	if username != "" || password != "" {
		fields["username"] = username
		fields["password"] = "[set]" // avoid logging password
	}
	logInfo("starting usque with configuration", fields)
}

// ------------------------ Endpoint ------------------------

func parseEndpoint(ep string) (host, port string, err error) {
	if ep == "" {
		return "", "", fmt.Errorf("empty endpoint")
	}

	if strings.HasPrefix(ep, "[") {
		end := strings.LastIndex(ep, "]")
		if end == -1 {
			return "", "", fmt.Errorf("invalid IPv6 format")
		}
		host = ep[1:end]
		if len(ep) > end+1 && ep[end+1] == ':' {
			port = ep[end+2:]
		}
	} else {
		colon := strings.LastIndex(ep, ":")
		if colon != -1 {
			host = ep[:colon]
			port = ep[colon+1:]
		} else {
			host = ep
		}
	}

	if port != "" {
		if err := validatePort(port); err != nil {
			return "", "", err
		}
	}

	return host, port, nil
}

func addEndpointToConfig(cfg map[string]interface{}, endpoint string) {
	if endpoint == "" {
		return
	}

	host, port, err := parseEndpoint(endpoint)
	if err != nil {
		logErrorAndExit(fmt.Sprintf("invalid endpoint: %v", err))
	}

	if port == "" {
		port = "443"
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			cfg["endpoint_v4"] = host
			cfg["endpoint_v4_port"] = port
			logInfo("using IPv4 endpoint", nil)
		} else {
			cfg["endpoint_v6"] = host
			cfg["endpoint_v6_port"] = port
			logInfo("using IPv6 endpoint", nil)
		}
		return
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		logErrorAndExit(fmt.Sprintf("failed to resolve %s: %v", host, err))
	}
	if len(ips) == 0 {
		logErrorAndExit(fmt.Sprintf("no IPs for %s", host))
	}

	var chosen net.IP
	hasV4, hasV6 := false, false
	for _, i := range ips {
		if i.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}

	preferV6 := useIpv6
	if preferV6 && !hasV6 {
		preferV6 = false
	} else if !preferV6 && !hasV4 {
		preferV6 = true
	}

	for _, i := range ips {
		if (preferV6 && i.To4() == nil) || (!preferV6 && i.To4() != nil) {
			chosen = i
			break
		}
	}
	if chosen == nil {
		chosen = ips[0]
	}

	isV6 := chosen.To4() == nil
	version := "v4"
	if isV6 {
		version = "v6"
	}
	cfg["endpoint_"+version] = chosen.String()
	cfg["endpoint_"+version+"_port"] = port
	logInfo(fmt.Sprintf("using resolved IPv%s endpoint for %s", map[bool]string{true: "6", false: "4"}[isV6], host), nil)
}

func needRegister(configFile string, renew bool) bool {
	if renew {
		return true
	}
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return true
	}
	return false
}

// ------------------------ Process & Scanner ------------------------

type procState struct {
	mu             sync.Mutex
	connected      bool
	privateKeyErr  bool
	endpointErr    bool
	handshakeFail  bool
	serveAddrShown bool
	tunnelFailCnt  int
}

func (st *procState) markConnected() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.connected = true
}

func runRegister(path string) error {
	cmd := exec.Command(path, "register", "-n", "masque-plus")
	stdin, _ := cmd.StdinPipe()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		stdin.Write([]byte("y\n"))
		time.Sleep(100 * time.Millisecond)
		stdin.Write([]byte("y\n"))
		stdin.Close()
	}()
	return cmd.Wait()
}

func createUsqueCmd(usquePath, config, bindIP, bindPort string, masquePort int, useV6 bool) *exec.Cmd {
	args := []string{"socks", "--config", config, "-b", bindIP, "-p", bindPort, "-P", strconv.Itoa(masquePort), "-s", sni}

	if useV6 {
		args = append(args, "-6")
	}
	if dnsStr != "" {
		for _, d := range splitCSV(dnsStr) {
			if ip := net.ParseIP(d); ip == nil {
				logInfo(fmt.Sprintf("warning: invalid DNS server %q; ignoring", d), nil)
				continue
			}
			args = append(args, "-d", d)
		}
	}
	args = append(args, "-t", dnsTimeout.String())
	args = append(args, "-i", strconv.Itoa(initialPacketSize))
	args = append(args, "-k", keepalivePeriod.String())
	if localDns {
		args = append(args, "-l")
	}
	args = append(args, "-m", strconv.Itoa(mtu))
	if noTunnelIpv4 {
		args = append(args, "-F")
	}
	if noTunnelIpv6 {
		args = append(args, "-S")
	}
	if username != "" && password != "" {
		args = append(args, "-u", username, "-w", password)
	} else if username != "" || password != "" {
		logInfo("warning: both --username and --password must be provided for authentication; ignoring", nil)
	}
	args = append(args, "-r", reconnectDelay.String())

	return exec.Command(usquePath, args...)
}

func runSocks(path, config, bindIP, bindPort string, connectTimeout time.Duration) error {
	cmd := createUsqueCmd(path, config, bindIP, bindPort, connectPort, useIpv6)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	state := &procState{}
	go handleScanner(bufio.NewScanner(stdout), bindIP+":"+bindPort, state, cmd, true, 3)
	go handleScanner(bufio.NewScanner(stderr), bindIP+":"+bindPort, state, cmd, true, 3)

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	start := time.Now()

	for {
		select {
		case err := <-waitCh:
			if state.privateKeyErr {
				return fmt.Errorf("failed to get private key")
			}
			if state.endpointErr {
				return fmt.Errorf("failed to set endpoint")
			}
			if state.handshakeFail {
				return fmt.Errorf("handshake failure")
			}
			return err

		default:
			state.mu.Lock()
			connected := state.connected
			state.mu.Unlock()

			if connected {
				select {}
			}

			if time.Since(start) > connectTimeout {
				_ = cmd.Process.Kill()
				return fmt.Errorf("connect timeout after %s", connectTimeout)
			}

			time.Sleep(200 * time.Millisecond)
		}
	}
}

func handleScanner(scan *bufio.Scanner, bind string, st *procState, cmd *exec.Cmd, logChild bool, tunnelFailLimit int) {
	if tunnelFailLimit <= 0 {
		tunnelFailLimit = 1
	}
	for scan.Scan() {
		line := scan.Text()
		lower := strings.ToLower(line)

		if logChild {
			logInfo(line, nil)
		}

		st.mu.Lock()
		switch {
		case strings.Contains(line, "Connected to MASQUE server"):
			if !st.serveAddrShown {
				logInfo("serving proxy", map[string]string{"address": bind})
				st.serveAddrShown = true
			}
			st.connected = true

		case strings.Contains(lower, "tls: handshake") ||
			strings.Contains(lower, "handshake failure") ||
			strings.Contains(lower, "crypto_error") ||
			strings.Contains(lower, "remote error"):
			st.handshakeFail = true
			_ = cmd.Process.Kill()

		case strings.Contains(lower, "invalid endpoint") ||
			strings.Contains(lower, "invalid sni") ||
			strings.Contains(lower, "dns resolution failed"):
			st.endpointErr = true
			_ = cmd.Process.Kill()

		case strings.Contains(lower, "login failed!"):
			_ = cmd.Process.Kill()

		case strings.Contains(lower, "failed to connect tunnel"):
			st.tunnelFailCnt++
			if st.tunnelFailCnt >= tunnelFailLimit {
				_ = cmd.Process.Kill()
			}

		case strings.Contains(lower, "failed to get private key"):
			st.privateKeyErr = true
			_ = cmd.Process.Kill()
		}
		st.mu.Unlock()
	}
}

// ------------------------ Logging ------------------------

func logInfo(msg string, fields map[string]string) {
	if fields == nil {
		fields = make(map[string]string)
	}
	logutil.Msg("INFO", msg, fields)
}

func logErrorAndExit(msg string) {
	logutil.Msg("ERROR", msg, nil)
	os.Exit(1)
}