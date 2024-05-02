package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	netsmtp "net/smtp"
	"net/textproto"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

var _ connector.PasswordConnector = &smtpConnector{}

type smtpConnector struct {
	logger log.Logger
	cfg    Config
}

func (sc *smtpConnector) Prompt() string {
	return sc.cfg.Label
}

func (sc *smtpConnector) Login(ctx context.Context, _ connector.Scopes, username, password string) (id connector.Identity, valid bool, err error) {
	
	// Read config

	h, p, err := net.SplitHostPort(sc.cfg.Host)
	if err != nil {
		return nil, false, err
	}
	sc.cfg.Host = h + ":" + p
	
	// Dial

	var conn net.Conn
	
    if p == "" || p == "465" {
		conn, err = tls.Dial("tcp", sc.cfg.Host, nil)
		if err != nil {
			return
		}
	} else {
		conn, err = net.Dial("tcp", sc.cfg.Host)
		if err != nil {
			return
		}
	}

	// Set client, defer quitting

	cli, err := netsmtp.NewClient(conn, h)
	defer cli.Quit()
	if err != nil {
		return
	}

	// Check domain

	name, domain, found := strings.Cut(username, "@")
	if found {
		if domain != sc.cfg.Domain {
			// username ends in something other than @$DOMAIN, so we reject it.
			valid = false
			err = nil
			return
		}
	} else {
		username += "@" + sc.cfg.Domain
	}

	// Auth and check

	auth := netsmtp.PlainAuth("", username, password, h)
	err = cli.Auth(auth)
	if te, ok := err.(*textproto.Error); ok {
		// These are normal "user/pass wrong" situations, so not an error.
		// see https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes
		if te.Code == 535 || te.Code == 454 {
			err = nil
			return
		}
	}
	if err != nil {
		return
	}

	// Prepare id

	id = connector.Identity{
		UserID:            username,
		Username:          name,
		PreferredUsername: name,
		Email:             username,
		EmailVerified:     true,
	}
	valid = true
	return
}

// Type Config holds all the config information for an SMTP
// connector.
type Config struct {
	// The host and port of the SMTP server.
	Host string `json:"host"`
	Domain string `json:"domain"`
	Label string `json:"label"`
}

func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	requiredFields := []struct {
		name string
		val  string
	}{
		{"host", c.Host},
		{"domain", c.Domain},
		{"label", c.Label},
	}

	for _, field := range requiredFields {
		if field.val == "" {
			return nil, fmt.Errorf("smtp: missing required field %q", field.name)
		}
	}

	return &smtpConnector{logger, *c}, nil
}
