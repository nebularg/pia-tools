package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jdelkins/pia-tools/internal/pia"
)

type CLI struct {
	IfName   string `short:"i" aliases:"ifname" default:"pia" help:"Name of WireGuard interface, used to determine cache filename."`
	Username string `short:"u" name:"username" env:"PIA_USERNAME" help:"PIA username (required if token expired)."`
	Password string `short:"p" name:"password" env:"PIA_PASSWORD" help:"PIA password (required if token expired)."`

	Refresh bool `short:"r" name:"refresh" help:"Refresh cached port assignment rather than requesting a new one."`

	ScriptDir string `short:"s" name:"script-dir" env:"PF_SCRIPT_DIR" type:"existingdir" help:"Directory of executables to run, in name order, after the port is bound, with tunnel and port forward details in PIA_* environment variables."`

	CacheDir string `short:"c" aliases:"cachedir" default:"/var/cache/pia" help:"Directory in which to store security-sensitive cache files."`
}

// scriptEnv returns the tunnel and port forward details as environment
// variable assignments, for consumption by user scripts. prevPort is the
// forwarded port from the previous run (0 if none). PIA_PF_PORT_PREVIOUS is
// empty if there was no previous port, and PIA_PF_PORT_CHANGED is empty if the
// port did not change. PIA_JSON holds the tunnel as JSON, minus keys and
// secrets.
func scriptEnv(tun *pia.Tunnel, prevPort int) ([]string, error) {
	tunJSON, err := scriptJSON(tun)
	if err != nil {
		return nil, err
	}
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
		{"PIA_JSON", tunJSON},
		// blank the credentials, which scripts would otherwise inherit
		{"PIA_USERNAME", ""},
		{"PIA_PASSWORD", ""},
	}
	env := make([]string, len(vars))
	for i, v := range vars {
		env[i] = v.name + "=" + v.value
	}
	return env, nil
}

// scriptJSON returns tun as JSON, with the fields that scriptEnv leaves out
// removed, as well as the private key.
func scriptJSON(tun *pia.Tunnel) (string, error) {
	b, err := json.Marshal(tun)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	delete(m, "server_key")
	delete(m, "peer_privkey")
	delete(m, "peer_pubkey")
	delete(m["token"].(map[string]any), "token")
	delete(m["PFSig"].(map[string]any), "signature")
	delete(m["PFSig"].(map[string]any), "payload")
	b, err = json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// listScripts returns the executable files in dir, sorted by name. Hidden
// files, directories, non-executable files and files not owned by root are
// skipped.
func listScripts(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var scripts []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		// stat rather than e.Info() so that symlinks are followed
		info, err := os.Stat(path)
		if err != nil {
			log.Printf("Skipping %s: %v", path, err)
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Mode().Perm()&0o111 == 0 {
			log.Printf("Skipping %s: not executable", path)
			continue
		}
		if info.Sys().(*syscall.Stat_t).Uid != 0 {
			log.Printf("Skipping %s: not owned by root", path)
			continue
		}
		scripts = append(scripts, path)
	}
	return scripts, nil
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

// forwardPort ensures we have a valid token, requests a new port forward
// assignment unless refresh is set and there is one to refresh, and binds it.
func forwardPort(tun *pia.Tunnel, username, password string, refresh bool) error {
	// ensure our token is still valid, if not grab a new one
	if !tun.Token.Valid() {
		if username == "" || password == "" {
			return errors.New("token expired and user/pass not provided")
		}
		if err := tun.NewToken(username, password); err != nil {
			return fmt.Errorf("could not refresh expired token: %w", err)
		}
	}

	// request new port unless refresh, or if a previous failure cleared it
	if !refresh || tun.PFSig.Signature == "" {
		if err := tun.NewPFSig(); err != nil {
			return fmt.Errorf("could not get port forwarding signature: %w", err)
		}
	}

	// bind the port to our virtual IP. If already active, effectuates the refresh
	if err := tun.BindPF(); err != nil {
		return fmt.Errorf("could not bind port forwarding assignment: %w", err)
	}
	return nil
}

func main() {
	var cli CLI
	kong.Parse(&cli, kong.Name("pia-portforward"))

	// failures are reported but do not stop the rest, so that user scripts
	// always run
	var failed []string

	// grab the cached tunnel info. Without it there is no port to forward and
	// nothing to cache, but scripts are still run, with port 0
	tun, err := pia.ReadCache(cli.CacheDir, cli.IfName)
	cached := err == nil
	if !cached {
		log.Printf("Could not read cache: %v", err)
		failed = append(failed, "cache")
		tun = &pia.Tunnel{Interface: cli.IfName, Status: "ERROR", Message: err.Error()}
	}
	prevPort := tun.PFSig.Port

	if cached {
		// on failure, cache port 0, so that scripts see the port change to 0
		// and then no further change while failures continue
		if err := forwardPort(tun, cli.Username, cli.Password, cli.Refresh); err != nil {
			log.Printf("Could not forward port: %v", err)
			failed = append(failed, "port forwarding")
			tun.PFSig = pia.PortForwardSig{}
			tun.Status = "ERROR"
			tun.Message = err.Error()
		}
		// save before running scripts, so a script that hangs can't lose it
		if err := tun.SaveCache(cli.CacheDir); err != nil {
			log.Printf("Could not save cache: %v", err)
			failed = append(failed, "cache")
		}
	}

	// run user scripts; a failure is reported but does not stop the rest
	if cli.ScriptDir != "" {
		scripts, err := listScripts(cli.ScriptDir)
		if err != nil {
			log.Printf("Could not read script directory %s: %v", cli.ScriptDir, err)
			failed = append(failed, "script directory "+cli.ScriptDir)
		}
		env, err := scriptEnv(tun, prevPort)
		if err != nil {
			log.Printf("Could not prepare script environment: %v", err)
			failed = append(failed, "script environment")
			scripts = nil
		} else {
			for _, script := range scripts {
				if err := runScript(script, env); err != nil {
					log.Printf("Script %s failed: %v", script, err)
					failed = append(failed, "script "+script)
				}
			}
		}
	}

	fmt.Printf("%s: %s (Port = %d)\n", tun.Status, tun.Message, tun.PFSig.Port)

	if len(failed) > 0 {
		log.Fatalf("Failed: %s", strings.Join(failed, ", "))
	}
}
