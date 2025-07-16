package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/tunnelx/sshr"
	envutil "github.com/projectdiscovery/utils/env"
	iputil "github.com/projectdiscovery/utils/ip"
	osutils "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/rs/xid"
	socks5 "github.com/things-go/go-socks5"
	"golang.org/x/crypto/ssh"
)

const version = "v0.0.1"

var (
	PunchHoleHost     = envutil.GetEnvOrDefault("PUNCH_HOLE_HOST", "proxy.projectdiscovery.io")
	PunchHolePort     = envutil.GetEnvOrDefault("PUNCH_HOLE_SSH_PORT", "20022")
	PunchHoleHTTPPort = envutil.GetEnvOrDefault("PUNCH_HOLE_HTTP_PORT", "8880")
	// proxy username is "pdcp" by default
	proxyUsername = envutil.GetEnvOrDefault("PROXY_USERNAME", "pdcp")

	AgentID = envutil.GetEnvOrDefault("AGENT_ID", xid.New().String())

	// CLI and env both args
	AgentName string
	// proxy password is the PDCP_API_KEY and is required
	proxyPassword string

	// NoColor is a flag to enable or disable color output
	noColor bool

	// showVersion is a flag to enable or disable version output
	showVersion bool

	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	logger      = log.Default()
	punchHoleIP string

	connectionSucceededCount int
)

type credentialStore struct {
	user     string
	password string
}

func (cs *credentialStore) Valid(user, password, userAddr string) bool {
	return user == cs.user && password == cs.password
}

var onceRemoteIp = sync.OnceValues(func() (string, error) {
	return getPublicIP()
})

var (
	socks5proxyPort  *freeport.Port
	reverseProxyPort *freeport.Port
	ctx              context.Context
	cancel           context.CancelFunc
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	if err := parseArguments(); err != nil {
		gologger.Fatal().Msgf("error parsing arguments: %v", err)
	}

	if showVersion {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	if noColor || osutils.IsWindows() {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}

	if err := process(); err != nil {
		gologger.Fatal().Msgf("%s", err)
	}
}

func process() error {
	if iputil.IsIP(PunchHoleHost) {
		punchHoleIP = PunchHoleHost
	} else {
		ips, err := net.LookupIP(PunchHoleHost)
		if err != nil {
			return errors.Wrapf(err, "error resolving %s", PunchHoleHost)
		}
		for _, ip := range ips {
			if iputil.IsIPv4(ip) {
				punchHoleIP = ip.String()
				break
			}
		}
		if punchHoleIP == "" {
			return errors.Errorf("no IPv4 address found for %s", PunchHoleHost)
		}
	}

	if proxyPassword == "" {
		return errors.Errorf("PDCP_API_KEY is not configured")
	}

	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithCredential(&credentialStore{user: proxyUsername, password: proxyPassword}),
	)

	var listenIp string
	// Check if the service is accessible from the internet
	accessible, err := isServiceAccessibleFromInternet()
	if err != nil {
		printConnectionFailure(errors.Wrap(err, "error checking service accessibility"))
	} else if accessible {
		listenIp, _ = onceRemoteIp()
		gologger.Print().Msgf("Service is accessible from the internet with ip: %s", listenIp)
	} else {
		gologger.Warning().Msgf("service is not accessible from the internet, listening on all interfaces")
		listenIp = "0.0.0.0"
	}

	socks5proxyPort, err = freeport.GetFreeTCPPort(listenIp)
	if err != nil {
		return errors.Wrap(err, "error getting free port")
	}

	if !accessible {
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()

		_ = Out(ctx)

		reverseProxyPort, err = getFreePortFromServer()
		if err != nil {
			printConnectionFailure(errors.Wrap(err, "error getting free port"))
		}

		// Register a graceful exit to call Out(ctx) when the program is interrupted
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			gologger.Print().Msg("Received interrupt signal, deregistering tunnel...")
			if err := Out(ctx); err != nil {
				gologger.Warning().Msgf("error deregistering tunnel: %v", err)
			}
			cancel()
			os.Exit(0)
		}()

		go func() {
			retryCount := 0
			for {
				if err := createTunnelsWithGoSSH(ctx); err != nil {
					gologger.Error().Msgf("error creating tunnels: %v", err)
					retryCount++
					if retryCount > 10 {
						gologger.Fatal().Msg("Exceeded maximum retry attempts for creating tunnels")
					}
					backoffDuration := time.Duration(retryCount*5) * time.Second
					time.Sleep(backoffDuration)
				} else {
					// reset retry count in case of success
					retryCount = 0
				}
			}
		}()
	} else {
		printConnectionSuccess()
	}

	if err := server.ListenAndServe("tcp", socks5proxyPort.NetListenAddress); err != nil {
		return errors.Wrap(err, "error listening and serving")
	}
	return nil
}

func printConnectionFailure(err error) {
	gologger.Error().Label("FTL").Msgf("%s", err)
	gologger.Info().Msgf("Check the following:")
	gologger.Print().Msgf("  - Verify your internet connection.")
	gologger.Print().Msgf("  - Ensure firewall or network settings permit the tunnel connection.")
	gologger.Print().Msgf("  - Confirm that your ProjectDiscovery API key is valid.")
	gologger.Print().Msgf("\n")
	gologger.Info().Label("HELP").Msgf("For further assistance, check the documentation or contact support.")
	os.Exit(1)
}

func printConnectionSuccess() {
	gologger.Info().Msgf("Session established. Leave this terminal open to enable continuous discovery and scanning.")
	gologger.Info().Msgf("Your network is a protected—connection, isolated and not exposed to the internet.")
	gologger.Info().Msgf("To create a scan, visit: https://cloud.projectdiscovery.io/scans")

	gologger.Print().Msgf("\n")
	gologger.Info().Label("HELP").Msgf("To terminate, press Ctrl+C.")
}

func parseArguments() error {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("A socks5 proxy server that tunnels traffic through a remote server")
	flagSet.SetCustomHelpText("USAGE EXAMPLE:\n  tunnelx -auth <your_api_key> -name <custom_network_name>")

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = xid.New().String()
	}

	flagSet.CreateGroup("Configuration", "Configuration",
		flagSet.StringVarEnv(&proxyPassword, "auth", "", "", "PDCP_API_KEY", "set your ProjectDiscovery API key for authentication"),
		flagSet.StringVarEnv(&AgentName, "name", "", hostname, "AGENT_NAME", "specify a network name (optional)"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&noColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
	)
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&showVersion, "version", false, "show version of the project"),
	)
	return flagSet.Parse()
}

func isServiceAccessibleFromInternet() (bool, error) {
	publicIP, err := onceRemoteIp()
	if err != nil {
		return false, err
	}

	localIPs, err := getLocalIPs()
	if err != nil {
		return false, err
	}

	return sliceutil.Contains(localIPs, publicIP), nil
}

func getPublicIP() (string, error) {
	resp, err := httpClient.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(ip)), nil
}

func getLocalIPs() ([]string, error) {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ip := addr.String()
			if iputil.IsIP(ip) {
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

func createTunnelsWithGoSSH(ctx context.Context) error {
	server := fmt.Sprintf("%s:%s", punchHoleIP, PunchHolePort)
	sshConfig := &ssh.ClientConfig{
		User: AgentID,
		Auth: []ssh.AuthMethod{
			ssh.Password(proxyPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	sshrConfig := &sshr.Config{
		SSHServer:        server,
		SSHClientConfig:  sshConfig,
		RemoteListenAddr: fmt.Sprintf("0.0.0.0:%d", reverseProxyPort.Port),
		LocalTarget:      fmt.Sprintf("localhost:%d", socks5proxyPort.Port),
		Logger:           slog.Default(),
		SuccessHook: func() {
			connectionSucceededCount++

			// Run the background /in routine for healthchecking
			go func() {
				if err := In(ctx); err != nil {
					printConnectionFailure(errors.Wrap(err, "error registering tunnel"))
				}
			}()
		},
	}
	s, err := sshr.New(*sshrConfig)
	if err != nil {
		return err
	}

	return s.Run(ctx)
}

func getFreePortFromServer() (*freeport.Port, error) {
	endpoint := fmt.Sprintf("http://%s:%s/freeport", punchHoleIP, PunchHoleHTTPPort)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", proxyPassword)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var result struct {
		Port int `json:"port"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	port := freeport.Port{Address: punchHoleIP, Port: result.Port, Protocol: freeport.TCP}

	return &port, nil
}

func In(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer func() {
		ticker.Stop()
		if err := Out(ctx); err != nil {
			gologger.Warning().Msgf("error deregistering tunnel: %v", err)
		}
		cancel()
	}()

	// Run first time to register
	if err := inFunctionTickCallback(ctx, true); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := inFunctionTickCallback(ctx, false); err != nil {
				return err
			}
		}
	}
}

func inFunctionTickCallback(ctx context.Context, first bool) error {
	endpoint := fmt.Sprintf("http://%s:%s/in", punchHoleIP, PunchHoleHTTPPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		log.Printf("failed to create request: %v", err)
		return err
	}
	q := req.URL.Query()
	q.Add("os", runtime.GOOS)
	q.Add("arch", runtime.GOARCH)
	q.Add("id", AgentID)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("X-API-Key", proxyPassword)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("failed to call /in endpoint: %v", err)
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("unexpected status code from /in endpoint: %d, body: %s", resp.StatusCode, string(body))
		return fmt.Errorf("unexpected status code from /in endpoint: %v, body: %s", resp.StatusCode, string(body))
	}
	time.Sleep(1000 * time.Millisecond)
	if first {
		if AgentName != "" {
			if err := renameAgent(ctx, AgentName); err != nil {
				gologger.Error().Msgf("error renaming agent: %v", err)
			}
		}
	}
	if connectionSucceededCount < 2 {
		connectionSucceededCount++
		printConnectionSuccess()
	}
	return nil
}

func Out(ctx context.Context) error {
	endpoint := fmt.Sprintf("http://%s:%s/out", punchHoleIP, PunchHoleHTTPPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		log.Printf("failed to create request: %v", err)
		return err
	}
	req.Header.Set("X-API-Key", proxyPassword)
	q := req.URL.Query()
	q.Add("id", AgentID)
	req.URL.RawQuery = q.Encode()
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("failed to call /out endpoint: %v", err)
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from /out endpoint: %v, body: %s", resp.StatusCode, string(body))
	}
	return nil
}

func renameAgent(ctx context.Context, name string) error {
	endpoint := fmt.Sprintf("http://%s:%s/rename", punchHoleIP, PunchHoleHTTPPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	q := req.URL.Query()
	q.Add("id", AgentID)
	q.Add("name", name)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("X-API-Key", proxyPassword)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call /rename endpoint: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from /rename endpoint: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}
