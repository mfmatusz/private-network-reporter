// Package reports provides email functionality for sending reports
package reports

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// EmailConfig holds SMTP configuration
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPass     string
	SMTPFrom     string
	SMTPTo       []string
	SMTPStartTLS bool
}

// Emailer handles report email sending
type Emailer struct {
	config EmailConfig
}

// NewEmailer creates a new email sender
func NewEmailer(config EmailConfig) *Emailer {
	return &Emailer{config: config}
}

// SendReport sends the HTML report via email
func (e *Emailer) SendReport(reportPath string, from, to time.Time) error {
	// Skip if not configured
	if e.config.SMTPHost == "" || len(e.config.SMTPTo) == 0 || e.config.SMTPFrom == "" {
		return nil // Not an error - just not configured
	}

	// Read report file
	body, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("failed to read report file: %w", err)
	}

	// Build email subject based on time range
	// Daily report (~24h) vs custom range
	duration := to.Sub(from)
	isDaily := duration >= 23*time.Hour && duration <= 25*time.Hour

	var subject string
	if isDaily {
		subject = fmt.Sprintf("LAN Daily Report %s", to.Format("2006-01-02"))
	} else {
		subject = fmt.Sprintf("LAN Report %s – %s", from.Format("2006-01-02"), to.Format("2006-01-02"))
	}

	msg := e.buildEmailMessage(e.config.SMTPFrom, e.config.SMTPTo, subject, string(body))
	addr := net.JoinHostPort(e.config.SMTPHost, e.config.SMTPPort)

	// Send with STARTTLS if configured
	if e.config.SMTPStartTLS {
		return e.sendWithSTARTTLS(addr, msg)
	}

	// Send without TLS (plain or implicit TLS)
	var auth smtp.Auth
	if e.config.SMTPUser != "" {
		auth = smtp.PlainAuth("", e.config.SMTPUser, e.config.SMTPPass, e.config.SMTPHost)
	}
	return smtp.SendMail(addr, auth, e.config.SMTPFrom, e.config.SMTPTo, []byte(msg))
}

// sendWithSTARTTLS sends email using STARTTLS
func (e *Emailer) sendWithSTARTTLS(addr, msg string) error {
	// Connect to SMTP server
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer c.Close()

	// Check STARTTLS support
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return fmt.Errorf("server does not support STARTTLS")
	}

	// Start TLS
	if err := c.StartTLS(&tls.Config{ServerName: e.config.SMTPHost}); err != nil {
		return fmt.Errorf("STARTTLS failed: %w", err)
	}

	// Authenticate if credentials provided
	if e.config.SMTPUser != "" {
		auth := smtp.PlainAuth("", e.config.SMTPUser, e.config.SMTPPass, e.config.SMTPHost)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Set sender
	if err := c.Mail(e.config.SMTPFrom); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Set recipients
	for _, rcpt := range e.config.SMTPTo {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %w", rcpt, err)
		}
	}

	// Send message body
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	if _, err := wc.Write([]byte(msg)); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close message: %w", err)
	}

	return nil
}

// buildEmailMessage constructs an RFC 5322 email message
func (e *Emailer) buildEmailMessage(from string, to []string, subject, html string) string {
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + html
}
