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
		"2606:4700:102::/48",
	}
	defaultBind           = "127.0.0.1:1080"
	defaultConfigFile     = "./config.json"
	defaultUsquePath      = "./usque"
	defaultConnectTimeout = 15 * time.Minute
	defaultTestURL        = "https://connectivity.cloudflareclient.com/cdn-cgi/trace" // kept for compatibility
)

func main() {
	endpoint := flag.String("endpoint", "", "Endpoint to connect (IPv4, IPv6; IP or IP:Port; for IPv6 with port use [IPv6]:Port)")
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
	dns := flag.String("dns", "1.1.1.1", "DNS (default 1.1.1.1, can be changed)")
	scanPerIP := flag.Duration("scan-timeout", 5*time.Second, "Per-endpoint scan timeout (dial+handshake)")
	scanMax := flag.Int("scan-max", 30, "Maximum number of endpoints to try during scan")
	scanVerboseChild := flag.Bool("scan-verbose-child", false, "Print MASQUE child process logs during scan")
	scanTunnelFailLimit := flag.Int("scan-tunnel-fail-limit", 2, "Number of 'Failed to connect tunnel' occurrences before skipping an endpoint")
	scanOrdered := flag.Bool("scan-ordered", false, "Scan candidates in CIDR order (disable shuffling)")
	jahesh := flag.Bool("jahesh", false, "Perform in-tunnel re-registration and restart to get a fresh egress IP")
	flag.Parse()

	_ = rtt
	_ = reserved
	_ = defaultTestURL // silence unused if not used elsewhere

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

		// NEW: shuffle candidates unless user asked for ordered scan
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
			bindAddr := fmt.Sprintf("%s:%s", bindIP, bindPort)

			// startFn: spin up usque for a single endpoint and wait up to scanPerIP for success
			// main.go (inside startFn in the --scan path)
			// startFn: spin up usque for a single endpoint and wait up to scanPerIP for success
			startFn := func(ep string) (func(), bool, error) {
				// load existing config (if any) and inject endpoint
				cmdCfg := make(map[string]interface{})
				if data, err := os.ReadFile(configFile); err == nil {
					_ = json.Unmarshal(data, &cmdCfg)
				}
				addEndpointToConfig(cmdCfg, ep)
				if err := writeConfig(configFile, cmdCfg); err != nil {
					return nil, false, err
				}

				// launch child (usque socks)
				cmd := exec.Command(usquePath, "socks", "--config", configFile, "-b", bindIP, "-p", bindPort, "-d", *dns)
				stdout, _ := cmd.StdoutPipe()
				stderr, _ := cmd.StderrPipe()

				if err := cmd.Start(); err != nil {
					return nil, false, err
				}

				st := &procState{}
				// forward/parse child logs (respect flags)
				go handleScanner(bufio.NewScanner(stdout), bindAddr, st, cmd, *scanVerboseChild, *scanTunnelFailLimit)
				go handleScanner(bufio.NewScanner(stderr), bindAddr, st, cmd, *scanVerboseChild, *scanTunnelFailLimit)

				// wait until connected or handshake failure or timeout
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

				// --- WARP check (no new flags, uses defaultTestURL) ---
				if ok {
					wcTimeout := *scanPerIP
					if wcTimeout <= 0 || wcTimeout > 5*time.Second {
						wcTimeout = 5 * time.Second
					}

					status, err := httpcheck.CheckWarpOverSocks(bindAddr, defaultTestURL, wcTimeout)
					fields := map[string]string{
						"endpoint": ep,
						"bind":     bindAddr,
						"status":   string(status),
						"url":      defaultTestURL,
						"timeout":  wcTimeout.String(),
					}
					if err != nil {
						fields["error"] = err.Error()
						logutil.Warn("warp check result", fields)
						// return stop, false, fmt.Errorf("warp check failed: %v", err)
					} else {
						logutil.Info("warp check result", fields)
						// if status != httpcheck.StatusOK { return stop, false, fmt.Errorf("warp not on") }
					}
				}
				// --- end WARP check ---

				return stop, ok, nil
			}

			// cap how many endpoints we try
			chosen, err := scanner.TryCandidates(
				candidates,
				*scanMax,
				*pingFlag,
				3*time.Second, // tcp probe timeout
				*scanPerIP,    // informational; startFn enforces it internally
				startFn,
			)
			if err != nil {
				logErrorAndExit(err.Error())
			}
			*endpoint = chosen
		}
	}

	if *jahesh {
		configFile := defaultConfigFile
		usquePath := defaultUsquePath

		if *endpoint == "" && !*scan {
			logErrorAndExit("--endpoint is required for --jahesh")
		}

		// Ensure we have an identity
		if needRegister(configFile, *renew) {
			if err := runRegister(usquePath); err != nil {
				logErrorAndExit(fmt.Sprintf("failed to register (initial): %v", err))
			}
			logInfo("initial identity created", nil)
		}

		// Load config and update endpoint fields
		cfg := make(map[string]interface{})
		if data, err := os.ReadFile(configFile); err == nil {
			_ = json.Unmarshal(data, &cfg)
		}
		addEndpointToConfig(cfg, *endpoint)
		if err := writeConfig(configFile, cfg); err != nil {
			logErrorAndExit(fmt.Sprintf("failed to write config: %v", err))
		}

		// Start a temporary SOCKS on a free port to perform in-tunnel register
		bindIP, bindPort := mustSplitBind(*bind)
		tempPort, err := pickFreePort()
		if err != nil {
			logErrorAndExit(fmt.Sprintf("pick temp port: %v", err))
		}

		tmpCmd, st, err := startSocksOnce(usquePath, configFile, bindIP, tempPort, true /*verbose*/, 3 /*tunnelFailLimit*/)
		if err != nil {
			logErrorAndExit(fmt.Sprintf("failed to start temporary socks: %v", err))
		}

		ok := waitConnected(st, tmpCmd, 10*time.Second)
		if !ok {
			gracefulStop(tmpCmd, 1500*time.Millisecond)
			logErrorAndExit("temporary tunnel not connected (timeout)")
		}

		// Register through the temporary SOCKS
		socksAddr := bindIP + ":" + tempPort
		if err := runRegisterViaSOCKS(usquePath, socksAddr); err != nil {
			gracefulStop(tmpCmd, 1500*time.Millisecond)
			logErrorAndExit(fmt.Sprintf("re-register via tunnel failed: %v", err))
		}

		// Stop temporary tunnel gracefully
		gracefulStop(tmpCmd, 1500*time.Millisecond)
		time.Sleep(250 * time.Millisecond) // let sockets settle

		// Reload config (now renewed) and re-apply endpoint
		cfg2 := make(map[string]interface{})
		if data, err := os.ReadFile(configFile); err == nil {
			_ = json.Unmarshal(data, &cfg2)
		}
		addEndpointToConfig(cfg2, *endpoint)
		if err := writeConfig(configFile, cfg2); err != nil {
			logErrorAndExit(fmt.Sprintf("failed to write config after jahesh: %v", err))
		}

		// Final SOCKS on the main --bind (fresh identity)
		if err := runSocks(usquePath, configFile, bindIP, bindPort, *connectTimeout); err != nil {
			logErrorAndExit(fmt.Sprintf("SOCKS start failed after jahesh: %v", err))
		}
		return
	}

	bindIP, bindPort := mustSplitBind(*bind)

	if needRegister(configFile, *renew) {
		if err := runRegister(usquePath); err != nil {
			logErrorAndExit(fmt.Sprintf("failed to register: %v", err))
		}
	}
	logInfo("successfully loaded masque identity", nil)

	// Load existing config if exists
	cfg := make(map[string]interface{})
	if data, err := os.ReadFile(configFile); err == nil {
		_ = json.Unmarshal(data, &cfg) // ignore parse errors for simplicity
	}

	// Update only endpoint fields
	addEndpointToConfig(cfg, *endpoint)

	// Write back full config
	if err := writeConfig(configFile, cfg); err != nil {
		logErrorAndExit(fmt.Sprintf("failed to write config: %v", err))
	}

	// Final SOCKS run (not scanning); keep child logs on and tolerate up to 3 tunnel fails
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

func startSocksOnce(path, config, bindIP, bindPort string, logChild bool, tunnelFailLimit int) (*exec.Cmd, *procState, error) {
    cmd := exec.Command(path, "socks", "--config", config, "-b", bindIP, "-p", bindPort)
    stdout, err := cmd.StdoutPipe()
    if err != nil { return nil, nil, err }
    stderr, err := cmd.StderrPipe()
    if err != nil { return nil, nil, err }
    if err := cmd.Start(); err != nil { return nil, nil, err }

    st := &procState{}
    go handleScanner(bufio.NewScanner(stdout), bindIP+":"+bindPort, st, cmd, logChild, tunnelFailLimit)
    go handleScanner(bufio.NewScanner(stderr), bindIP+":"+bindPort, st, cmd, logChild, tunnelFailLimit)
    return cmd, st, nil
}

func waitConnected(st *procState, cmd *exec.Cmd, timeout time.Duration) bool {
    deadline := time.Now().Add(timeout)
    waitCh := make(chan error, 1)
    go func() { waitCh <- cmd.Wait() }()
    for time.Now().Before(deadline) {
        select {
        case <-time.After(120 * time.Millisecond):
            st.mu.Lock()
            ok := st.connected
            hs := st.handshakeFail
            st.mu.Unlock()
            if ok { return true }
            if hs { return false }
        case err := <-waitCh:
            _ = err
            return false
        }
    }
    return false
}

func runRegisterViaSOCKS(path, socksAddr string) error {
    cmd := exec.Command(path, "register", "-n", "masque-plus")
    stdin, _ := cmd.StdinPipe()
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    proxyURL := "socks5://" + socksAddr
    env := os.Environ()
    env = append(env,
        "ALL_PROXY="+proxyURL,
        "HTTPS_PROXY="+proxyURL,
        "HTTP_PROXY="+proxyURL,
        "NO_PROXY=",
    )
    cmd.Env = env
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

func gracefulStop(cmd *exec.Cmd, wait time.Duration) {
    if cmd == nil || cmd.Process == nil { return }
    _ = cmd.Process.Signal(os.Interrupt)
    done := make(chan struct{}, 1)
    go func() { _ = cmd.Wait(); close(done) }()
    select {
    case <-done:
        return
    case <-time.After(wait):
        _ = cmd.Process.Kill()
        <-done
        return
    }
}

func pickFreePort() (string, error) {
    l, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil { return "", err }
    addr := l.Addr().(*net.TCPAddr)
    port := strconv.Itoa(addr.Port)
    _ = l.Close()
    return port, nil
}

// ------------------------ Endpoint ------------------------

func parseEndpoint(ep string) (net.IP, string, error) {
	if ep == "" {
		return nil, "", fmt.Errorf("empty endpoint")
	}
	var ipStr, port string

	if strings.HasPrefix(ep, "[") { // IPv6 with port [::1]:443
		end := strings.Index(ep, "]")
		if end == -1 {
			return nil, "", fmt.Errorf("invalid IPv6 format")
		}
		ipStr = ep[1:end]
		if len(ep) > end+1 && ep[end+1] == ':' {
			port = ep[end+2:]
		}
	} else if strings.Count(ep, ":") > 1 { // plain IPv6 without port
		ipStr = ep
	} else if strings.Contains(ep, ":") { // IPv4:port
		parts := strings.SplitN(ep, ":", 2)
		ipStr = parts[0]
		port = parts[1]
	} else { // IPv4 without port
		ipStr = ep
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, "", fmt.Errorf("invalid IP %q", ipStr)
	}
	return ip, port, nil
}

func addEndpointToConfig(cfg map[string]interface{}, endpoint string) {
	ip, port, err := parseEndpoint(endpoint)
	if err != nil {
		logErrorAndExit(fmt.Sprintf("invalid endpoint: %v", err))
	}

	if ip.To4() != nil {
		cfg["endpoint_v4"] = ip.String()
		if port != "" {
			cfg["endpoint_v4_port"] = port
		}
		logInfo("using IPv4 endpoint", nil)
	} else {
		cfg["endpoint_v6"] = ip.String()
		if port != "" {
			cfg["endpoint_v6_port"] = port
		}
		logInfo("using IPv6 endpoint", nil)
	}
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

func runSocks(path, config, bindIP, bindPort string, connectTimeout time.Duration) error {
	cmd := exec.Command(path, "socks", "--config", config, "-b", bindIP, "-p", bindPort)

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
	// during final run we do want to see child logs; allow a few tunnel retries
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
				//logInfo("Proxy is serving", map[string]string{"bind": bindIP + ":" + bindPort})
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

// handleScanner parses child process lines and mutates state.
// logChild: print child raw lines if true; tunnelFailLimit: kill after N "Failed to connect tunnel" lines.
func handleScanner(scan *bufio.Scanner, bind string, st *procState, cmd *exec.Cmd, logChild bool, tunnelFailLimit int) {
	if tunnelFailLimit <= 0 {
		tunnelFailLimit = 1
	}
	for scan.Scan() {
		line := scan.Text()
		lower := strings.ToLower(line)

		if logChild {
            if strings.Contains(lower, "wsarecv: an existing connection was forcibly closed") ||
            strings.Contains(lower, "wsarecv: an established connection was aborted")  ||
            strings.Contains(lower, "datagram frame too large") {
                // ignore noisy windows socket errors during switch
            } else {
                logInfo(line, nil)
            }
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

		case strings.Contains(lower, "invalid endpoint"):
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
func logErrorAndExit(msg string) { logutil.Msg("ERROR", msg, nil); os.Exit(1) }
