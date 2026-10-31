package main

import (
	"encoding/json"
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

	ScriptDir string `short:"s" name:"script-dir" env:"PORTFORWARD_SCRIPT_DIR" type:"existingdir" help:"Directory of executables to run, in name order, after the port is bound, with tunnel and port forward details in PIA_* environment variables."`

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
			log.Panicf("Could not refresh expired token: %v", err)
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

	// run user scripts; a failure is reported but does not stop the rest
	var failed []string
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
		}
		for _, script := range scripts {
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
