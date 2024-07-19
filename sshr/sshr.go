package sshr

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"golang.org/x/crypto/ssh"
)

type SSHR struct {
	config Config
}

// Config for Tun
type Config struct {
	LocalTarget      string
	RemoteListenAddr string
	SSHServer        string

	SSHClientConfig *ssh.ClientConfig

	Logger *slog.Logger
}

// New tun.
func New(config Config) (*SSHR, error) {
	config.SSHClientConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	return &SSHR{config: config}, nil
}

func (s *SSHR) Run(ctx context.Context) error {
	conn, err := ssh.Dial("tcp", s.config.SSHServer, s.config.SSHClientConfig)
	if err != nil {
		return fmt.Errorf("error dialing [%s]: %v", s.config.SSHServer, err)
	}
	defer conn.Close()

	listener, err := conn.Listen("tcp", s.config.RemoteListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("error accepting connection: %v", err)
		}

		err = s.handleConn(conn)
		if err != nil {
			s.config.Logger.Error("error handling connection",
				slog.String("remote_addr", conn.RemoteAddr().String()),
				slog.String("error", err.Error()),
			)
			continue
		}
	}
}

func (s *SSHR) handleConn(conn net.Conn) error {
	s.config.Logger.Info("forwarding connection",
		slog.String("remote_addr", conn.RemoteAddr().String()),
		slog.String("local_target", s.config.LocalTarget),
	)
	proxyConn, err := net.Dial("tcp", s.config.LocalTarget)
	if err != nil {
		return err
	}

	go func() {
		_, err := io.Copy(proxyConn, conn)
		if err != nil && err != io.EOF {
			s.config.Logger.Error("copy data error",
				slog.String("direction", "punch-hole -> tunnelx -> proxy"),
				slog.String("error", err.Error()),
			)
		}
		s.config.Logger.Info("closed connection",
			slog.String("direction", "punch-hole -> tunnelx -> proxy"),
		)
	}()

	go func() {
		_, err := io.Copy(conn, proxyConn)
		if err != nil && err != io.EOF {
			s.config.Logger.Error("copy data error",
				slog.String("direction", "proxy -> tunnelx -> punch-hole"),
				slog.String("error", err.Error()),
			)
		}
		s.config.Logger.Info("closed connection",
			slog.String("direction", "proxy -> tunnelx -> punch-hole"),
		)
	}()
	return nil
}
