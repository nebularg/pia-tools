package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jdelkins/pia-tools/internal/pia"
	"github.com/jdelkins/pia-tools/internal/qbittorrent"
	"github.com/jdelkins/pia-tools/internal/rtorrent"
	"github.com/jdelkins/pia-tools/internal/transmission"
)

type CLI struct {
	IfName   string `short:"i" aliases:"ifname" default:"pia" help:"Name of WireGuard interface, used to determine cache filename."`
	Username string `short:"u" name:"username" env:"PIA_USERNAME" help:"PIA username (required if token expired)."`
	Password string `short:"p" name:"password" env:"PIA_PASSWORD" help:"PIA password (required if token expired)."`

	Refresh bool `short:"r" name:"refresh" help:"Refresh cached port assignment rather than requesting a new one."`

	Rtorrent      string `name:"rtorrent" env:"RTORRENT" help:"XML-RPC URL of rtorrent server (for port forward notifications)."`
	Transmission  string `name:"transmission" env:"TRANSMISSION" help:"URL of transmission server RPC endpoint (for port forward notifications)."`
	TransUser     string `name:"transmission-username" env:"TRANSMISSION_USERNAME" help:"Transmission server username."`
	TransPassword string `name:"transmission-password" env:"TRANSMISSION_PASSWORD" help:"Transmission server password."`
	Qbittorrent   string `name:"qbittorrent" env:"QBITTORRENT" help:"URL of qbittorrent WebUI API endpoint."`
	QbtApiKey     string `name:"qbittorrent-apikey" env:"QBITTORRENT_APIKEY" help:"The qbittorrent WebUI API key."`
	QbtUser       string `name:"qbittorrent-username" env:"QBITTORRENT_USERNAME" help:"The qbittorrent WebUI username."`
	QbtPassword   string `name:"qbittorrent-password" env:"QBITTORRENT_PASSWORD" help:"The qbittorrent WebUI password."`

	Scripts []string `short:"s" name:"script" type:"path" sep:"none" help:"Executable to run after the port is bound, with tunnel and port forward details in PIA_* environment variables. May be repeated."`

	CacheDir string `short:"c" aliases:"cachedir" default:"/var/cache/pia" help:"Directory in which to store security-sensitive cache files."`
}

// scriptEnv returns the tunnel and port forward details as environment
// variable assignments, for consumption by user scripts. prevPort is the
// forwarded port from the previous run (0 if none). PIA_PF_PORT_PREVIOUS is
// empty if there was no previous port, and PIA_PF_PORT_CHANGED is empty if the
// port did not change.
func scriptEnv(tun *pia.Tunnel, prevPort int) []string {
	previous := ""
	if prevPort != 0 {
		previous = strconv.Itoa(prevPort)
	}
	changed := ""
	if tun.PFSig.Port != prevPort {
		changed = "1"
	}
	vars := []struct{ name, value string }{
		{"PIA_INTERFACE", tun.Interface},
		{"PIA_STATUS", tun.Status},
		{"PIA_MESSAGE", tun.Message},
		{"PIA_REGION_ID", tun.Region.Id},
		{"PIA_REGION_NAME", tun.Region.Name},
		// {"PIA_SERVER_PUBKEY", tun.ServerPubkey},
		{"PIA_SERVER_PORT", strconv.Itoa(tun.ServerPort)},
		{"PIA_SERVER_IP", tun.ServerIp},
		{"PIA_SERVER_VIP", tun.ServerVip},
		{"PIA_PEER_IP", tun.PeerIp},
		// {"PIA_PEER_PUBKEY", tun.PublicKey},
		{"PIA_DNS_SERVERS", strings.Join(tun.DnsServers, " ")},
		// {"PIA_TOKEN", tun.Token.Token},
		{"PIA_TOKEN_EXPIRY", tun.Token.Expiry.Format(time.RFC3339)},
		{"PIA_PF_PORT", strconv.Itoa(tun.PFSig.Port)},
		{"PIA_PF_PORT_PREVIOUS", previous},
		{"PIA_PF_PORT_CHANGED", changed},
		{"PIA_PF_EXPIRY", tun.PFSig.Expiry.Format(time.RFC3339)},
		// {"PIA_PF_SIGNATURE", tun.PFSig.Signature},
		// {"PIA_PF_PAYLOAD", tun.PFSig.Payload},
	}
	env := make([]string, len(vars))
	for i, v := range vars {
		env[i] = v.name + "=" + v.value
	}
	return env
}

// runScript executes the script at path, passing through our environment
// plus env, and connecting its output to ours.
func runScript(path string, env []string) error {
	cmd := exec.Command(path)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// notifyRtorrent sets rtorrent's listening port, returning the port rtorrent
// reports afterwards.
func notifyRtorrent(url string, port int) (int, error) {
	if err := rtorrent.Notify(url, port); err != nil {
		return 0, fmt.Errorf("could not notify rtorrent (at %s) of assigned port: %w", url, err)
	}
	port, err := rtorrent.Confirm(url)
	if err != nil {
		return 0, fmt.Errorf("could not verify rtorrent port: %w", err)
	}
	return port, nil
}

// notifyTransmission sets transmission's peer port, returning the port
// transmission reports afterwards.
func notifyTransmission(url, user, password string, port int) (int, error) {
	if err := transmission.Notify(url, user, password, port); err != nil {
		return 0, fmt.Errorf("could not notify transmission (at %s) of assigned port: %w", url, err)
	}
	port, err := transmission.Confirm(url, user, password)
	if err != nil {
		return 0, fmt.Errorf("could not verify transmission port: %w", err)
	}
	return port, nil
}

// notifyQbittorrent sets qbittorrent's listening port, returning the port
// qbittorrent reports afterwards. The api key is preferred if set; otherwise
// a session is opened with user/password, if given.
func notifyQbittorrent(url, apiKey, user, password string, port int) (int, error) {
	var sessionCookie *http.Cookie
	if apiKey == "" && user != "" && password != "" {
		cookie, err := qbittorrent.Login(url, user, password)
		if err != nil {
			return 0, fmt.Errorf("could not login to qbittorrent (at %s): %w", url, err)
		}
		sessionCookie = cookie
		defer func() {
			if err := qbittorrent.Logout(url, sessionCookie); err != nil {
				log.Printf("Failed to logout of qbittorrent: %v", err)
			}
		}()
	}
	if err := qbittorrent.Notify(url, apiKey, sessionCookie, port); err != nil {
		return 0, fmt.Errorf("could not notify qbittorrent (at %s) of assigned port: %w", url, err)
	}
	port, err := qbittorrent.Confirm(url, apiKey, sessionCookie)
	if err != nil {
		return 0, fmt.Errorf("could not verify qbittorrent port: %w", err)
	}
	return port, nil
}

func main() {
	var cli CLI
	kong.Parse(&cli, kong.Name("pia-portforward"))

	// grab the cached tunnel info
	tun, err := pia.ReadCache(cli.CacheDir, cli.IfName)
	if err != nil {
		log.Panicf("Could not read cache: %v", err)
	}
	prevPort := tun.PFSig.Port
	defer func() {
		if err := tun.SaveCache(cli.CacheDir); err != nil {
			log.Panicf("Could not save cache: %v", err)
		}
	}()

	// ensure our token is still valid, if not grab a new one
	if !tun.Token.Valid() {
		if cli.Username == "" || cli.Password == "" {
			log.Panicf("Token expired and user/pass not provided")
		}
		if err := tun.NewToken(cli.Username, cli.Password); err != nil {
			log.Panicf("Token expired; error refreshing: %v", err)
		}
	}

	// request new port unless --refresh
	if !cli.Refresh {
		if err := tun.NewPFSig(); err != nil {
			log.Panicf("Could not get port forwarding signature: %v", err)
		}
	}

	// bind the port to our virtual IP. If already active, effectuates the refresh
	if err := tun.BindPF(); err != nil {
		log.Panicf("Could not bind port forwarding assignment: %v", err)
	}

	// notify torrent clients and run user scripts; a failure is reported but
	// does not stop the rest
	var failed []string
	checkClient := func(client string, port int, err error) {
		if err == nil && port != tun.PFSig.Port {
			err = fmt.Errorf("PIA assigned us port %d, but %s reports port is %d", tun.PFSig.Port, client, port)
		}
		if err != nil {
			log.Printf("Could not update %s: %v", client, err)
			failed = append(failed, client)
		}
	}

	if cli.Rtorrent != "" {
		port, err := notifyRtorrent(cli.Rtorrent, tun.PFSig.Port)
		checkClient("rtorrent", port, err)
	}

	if cli.Transmission != "" {
		port, err := notifyTransmission(cli.Transmission, cli.TransUser, cli.TransPassword, tun.PFSig.Port)
		checkClient("transmission", port, err)
	}

	if cli.Qbittorrent != "" {
		port, err := notifyQbittorrent(cli.Qbittorrent, cli.QbtApiKey, cli.QbtUser, cli.QbtPassword, tun.PFSig.Port)
		checkClient("qbittorrent", port, err)
	}

	if len(cli.Scripts) > 0 {
		env := scriptEnv(tun, prevPort)
		for _, script := range cli.Scripts {
			if err := runScript(script, env); err != nil {
				log.Printf("Script %s failed: %v", script, err)
				failed = append(failed, "script "+script)
			}
		}
	}

	fmt.Printf("%s: %s (Port = %d)\n", tun.Status, tun.Message, tun.PFSig.Port)

	if len(failed) > 0 {
		log.Panicf("Failed: %s", strings.Join(failed, ", "))
	}
}
