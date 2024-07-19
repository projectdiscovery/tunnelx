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

	socks5 "github.com/armon/go-socks5"
	"github.com/projectdiscovery/freeport"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tunnelx/sshr"
	envutil "github.com/projectdiscovery/utils/env"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"golang.org/x/crypto/ssh"
)

var (
	PunchHoleHost     = envutil.GetEnvOrDefault("PUNCH_HOLE_HOST", "proxy-dev.projectdiscovery.io")
	PunchHolePort     = envutil.GetEnvOrDefault("PUNCH_HOLE_SSH_PORT", "20022")
	PunchHoleHTTPPort = envutil.GetEnvOrDefault("PUNCH_HOLE_HTTP_PORT", "8880")
	// proxy username is "pdcp" by default
	proxyUsername = envutil.GetEnvOrDefault("PROXY_USERNAME", "pdcp")
	// proxy password is the PDCP_API_KEY and is required
	proxyPassword = envutil.GetEnvOrDefault("PDCP_API_KEY", "")

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
)

type credentialStore struct {
	user     string
	password string
}

func (cs *credentialStore) Valid(user, password string) bool {
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
	if iputil.IsIP(PunchHoleHost) {
		punchHoleIP = PunchHoleHost
	} else {
		ips, err := net.LookupIP(PunchHoleHost)
		if err != nil {
			gologger.Fatal().Msgf("error resolving %s: %v", PunchHoleHost, err)
		}
		for _, ip := range ips {
			if iputil.IsIPv4(ip) {
				punchHoleIP = ip.String()
				break
			}
		}
		if punchHoleIP == "" {
			gologger.Fatal().Msgf("no IPv4 address found for %s", PunchHoleHost)
		}
	}

	conf := &socks5.Config{
		Logger: logger,
	}

	if proxyPassword == "" {
		gologger.Fatal().Msgf("PDCP_API_KEY is not configured")
	}

	auth := socks5.UserPassAuthenticator{
		Credentials: &credentialStore{user: proxyUsername, password: proxyPassword},
	}
	conf.AuthMethods = []socks5.Authenticator{auth}

	server, err := socks5.New(conf)
	if err != nil {
		gologger.Fatal().Msgf("error creating socks5 server: %v", err)
	}

	var listenIp string
	// Check if the service is accessible from the internet
	accessible, err := isServiceAccessibleFromInternet()
	if err != nil {
		gologger.Fatal().Msgf("error checking service accessibility: %v", err)
	} else if accessible {
		listenIp, _ = onceRemoteIp()
		gologger.Print().Msgf("Service is accessible from the internet with ip: %s", listenIp)
	} else {
		gologger.Warning().Msgf("service is not accessible from the internet, listening on all interfaces")
		listenIp = "0.0.0.0"
	}

	socks5proxyPort, err = freeport.GetFreeTCPPort(listenIp)
	if err != nil {
		gologger.Fatal().Msgf("error getting free port: %v", err)
	}

	gologger.Print().Msgf("Socks5 proxy listening on: %s", socks5proxyPort.Address)

	if !accessible {
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()

		// deregister existing tunnel if any
		_ = Out(ctx)

		reverseProxyPort, err = getFreePortFromServer()
		if err != nil {
			gologger.Fatal().Msgf("error getting free port: %v", err)
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
	}

	if err := server.ListenAndServe("tcp", socks5proxyPort.Address); err != nil {
		gologger.Fatal().Msgf("error listening and serving: %v", err)
	}
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
	defer resp.Body.Close()

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
		User: proxyUsername,
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
	}
	s, err := sshr.New(*sshrConfig)
	if err != nil {
		return err
	}

	gologger.Print().Msgf("Your tunnel is: %s:%d", punchHoleIP, reverseProxyPort.Port)

	go func() {
		if err := In(ctx); err != nil {
			gologger.Fatal().Msgf("error registering tunnel: %v", err)
		}
	}()

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
	defer resp.Body.Close()

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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			endpoint := fmt.Sprintf("http://%s:%s/in", punchHoleIP, PunchHoleHTTPPort)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
			if err != nil {
				log.Printf("failed to create request: %v", err)
				return err
			}
			q := req.URL.Query()
			q.Add("os", runtime.GOOS)
			q.Add("arch", runtime.GOARCH)
			req.URL.RawQuery = q.Encode()
			req.Header.Set("X-API-Key", proxyPassword)
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("failed to call /in endpoint: %v", err)
				return err
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("failed to read response body: %v", err)
				return err
			}
			if resp.StatusCode != http.StatusOK {
				log.Printf("unexpected status code from /in endpoint: %d, body: %s", resp.StatusCode, string(body))
				return fmt.Errorf("unexpected status code from /in endpoint: %v, body: %s", resp.StatusCode, string(body))
			}
		}
	}
}

func Out(ctx context.Context) error {
	endpoint := fmt.Sprintf("http://%s:%s/out", punchHoleIP, PunchHoleHTTPPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		log.Printf("failed to create request: %v", err)
		return err
	}
	req.Header.Set("X-API-Key", proxyPassword)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("failed to call /out endpoint: %v", err)
		return err
	}
	defer resp.Body.Close()
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
