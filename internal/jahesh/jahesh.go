package jahesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/net/proxy"
)

type Registrar func(ctx context.Context, httpc *http.Client) (configJSON []byte, err error)

type Opts struct {
	UsqueBin string
	Endpoint string
	Bind string
	ConfigPath string
	SOCKSReadyTimeout    time.Duration 
	GracefulStopDuration time.Duration
	Logf func(format string, args ...any)
}

func Run(ctx context.Context, o Opts, registrar Registrar) error {
	if registrar == nil {
		return errors.New("jahesh: registrar is nil")
	}
	if o.Endpoint == "" {
		return errors.New("jahesh: endpoint is required")
	}
	if o.Bind == "" {
		o.Bind = "127.0.0.1:1080"
	}
	if o.ConfigPath == "" {
		o.ConfigPath = "config.json"
	}
	if o.SOCKSReadyTimeout == 0 {
		o.SOCKSReadyTimeout = 10 * time.Second
	}
	if o.GracefulStopDuration == 0 {
		o.GracefulStopDuration = 2 * time.Second
	}
	if o.UsqueBin == "" {
		if bin, err := detectUsqueBinary(); err == nil {
			o.UsqueBin = bin
		} else {
			return fmt.Errorf("jahesh: detect usque: %w", err)
		}
	}
	logf := o.Logf
	if logf == nil {
		logf = func(format string, args ...any) {
			// silent by default; uncomment for verbose:
			// fmt.Printf("[jahesh] "+format+"\n", args...)
		}
	}

	logf("starting initial usque on %s (endpoint %s)", o.Bind, o.Endpoint)
	up, err := startUsque(o.UsqueBin, o.Endpoint, o.Bind, nil)
	if err != nil {
		return fmt.Errorf("start usque: %w", err)
	}
	defer func() {
		// safety net
		if up != nil {
			stopUsque(up, o.GracefulStopDuration)
		}
	}()

	if err := waitSOCKSReady(o.Bind, o.SOCKSReadyTimeout); err != nil {
		stopUsque(up, o.GracefulStopDuration)
		return fmt.Errorf("wait socks: %w", err)
	}

	logf("building http client over SOCKS %s", o.Bind)
	httpc, err := httpClientViaSOCKS(o.Bind)
	if err != nil {
		stopUsque(up, o.GracefulStopDuration)
		return fmt.Errorf("http via socks: %w", err)
	}

	regCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	logf("calling registrar (in-tunnel re-registration)")
	cfgJSON, err := registrar(regCtx, httpc)
	if err != nil {
		stopUsque(up, o.GracefulStopDuration)
		return fmt.Errorf("registrar failed: %w", err)
	}
	if !json.Valid(cfgJSON) {
		stopUsque(up, o.GracefulStopDuration)
		return fmt.Errorf("registrar returned invalid JSON")
	}

	if err := os.WriteFile(o.ConfigPath, cfgJSON, 0600); err != nil {
		stopUsque(up, o.GracefulStopDuration)
		return fmt.Errorf("write config: %w", err)
	}
	logf("wrote new config to %s (%d bytes)", o.ConfigPath, len(cfgJSON))

	logf("stopping old usque")
	stopUsque(up, o.GracefulStopDuration)
	up = nil

	logf("starting new usque on %s (endpoint %s)", o.Bind, o.Endpoint)
	up2, err := startUsque(o.UsqueBin, o.Endpoint, o.Bind, nil)
	if err != nil {
		return fmt.Errorf("start usque (new): %w", err)
	}
	defer func() {
		if up2 != nil {
			stopUsque(up2, o.GracefulStopDuration)
		}
	}()

	if err := waitSOCKSReady(o.Bind, o.SOCKSReadyTimeout); err != nil {
		stopUsque(up2, o.GracefulStopDuration)
		return fmt.Errorf("wait socks (new): %w", err)
	}

	logf("jahesh completed successfully")
	return nil
}

// ---------- helpers ----------

type UsqueProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func startUsque(binPath, endpoint, bind string, extraEnv []string) (*UsqueProc, error) {
	args := []string{
		"--endpoint", endpoint,
		"--bind", bind,             // SOCKS5 local bind, like 127.0.0.1:1080
		"--config", "config.json",  
	}
	cmd := exec.Command(binPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), extraEnv...)

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	up := &UsqueProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(up.done)
	}()
	return up, nil
}

func stopUsque(up *UsqueProc, gracefulWait time.Duration) {
	if up == nil || up.cmd == nil || up.cmd.Process == nil {
		return
	}
	_ = up.cmd.Process.Signal(os.Interrupt)
	select {
	case <-up.done:
	case <-time.After(gracefulWait):
		_ = up.cmd.Process.Kill()
		<-up.done
	}
}

func waitSOCKSReady(bind string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", bind, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("SOCKS not ready on %s within %s", bind, timeout)
}

func httpClientViaSOCKS(socksAddr string) (*http.Client, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(network, addr)
	}
	transport := &http.Transport{
		DialContext: dialer,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

func detectUsqueBinary() (string, error) {
	exe, _ := os.Executable()
	if exe != "" {
		dir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(dir, "usque"),
			filepath.Join(dir, "usque.exe"),
		}
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c, nil
			}
		}
	}
	// سپس PATH
	if p, err := exec.LookPath("usque"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("usque.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("usque binary not found (put it next to launcher or in PATH)")
}