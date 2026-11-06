# pia-tools

A suite of tools for establishing a [WireGuard][wireguard] tunnel to [Private
Internet Access][PIA] on Linux using [systemd-networkd][], based on [PIA’s REST
API](https://github.com/pia-foss/manual-connections). It can also manage PIA’s
port forwarding feature and run your own scripts with the assigned port, e.g. to
tell a BitTorrent client about it; this will allow receiving incoming BitTorrent
peer connections over the VPN.

A helper utility, `pia-listregions`, will show you, on your terminal, a ranked
(by latency) list of PIA servers, with some possibly-salient info about them,
with the goal of helping you choose the 'best' region to connect to if you are
otherwise indifferent about their geography.

## Stability and Usability

This code is tested with only my own private setup. It may or may not work for
you, and if it does, some assembly will be required by you. That said, I have
used and developed it for a few years, and really enjoy the low-maintenance
functionality and peace of mind it provides for me.

These tools don't do anything exotic; they generate configuration
files and then standard system tools apply them. Nevertheless, it is for a
fairly advanced use case, not something for the average consumer.

If you identify additional features or encounter problems, I encourage you to
submit an issue or PR.

If you use this on a remote firewall, ensure you have out-of-band access before
experimenting with routing.

## Security Model

- The cache contains WireGuard private keys and PIA API auth material (e.g.,
  tokens/port-forward signatures). Treat it as sensitive.

- A new WireGuard keypair is generated each time the tunnel is (re-)established.

- The tools read PIA username/password (from flags or the environment) but do
  not persist them to disk.

- API calls and cache updates can be performed as an unprivileged service
  account.

- Root privileges are required only to write into privileged locations
  (`/etc/systemd/network`), to apply link changes, and to run port forwarding
  scripts, which may need to change system configuration (e.g. firewall rules).

- Intended to be automated via systemd; the included units invoke standard
  system tools (`networkctl`, `ip`) to activate changes.

## Quick Start

See [Manual Install](#manual-install) and the example units in [`./systemd`](./systemd)

1. Install tools
2. Write templates, or copy and modify the examples
3. Create a `pia` service account
4. Write environment file containing your credentials
5. Install and activate systemd service and timer
6. (Optional) Configure and activate port forwarding service and timer

## About

[Private Internet Access][PIA] is, in my opinion, a solid VPN provider.[^1]
In their latest generation infrastructure, they designed a system for use by
their mobile and desktop apps, which allow WireGuard tunnels with randomly
generated, frequently rotated private keys. Unfortunately, their Linux app,
though I haven't tried it, doesn't feel right for my use case, wherein I run
the VPN on my firewall, a Linux box running [systemd-networkd][], in the manner
described below. Luckily, however, [PIA][] published their REST API, which
is pretty simple to use; powered by that, we can dynamically configure our
systemd-networkd managed VPN tunnel and routing rules with this tool suite.

[PIA][]'s VPN service includes a dynamic port forwarding feature that allows
you to run a server on or behind your VPN endpoint. This suite can help you
with that.

Because of the dynamic nature of your endpoint public and virtual IP addresses,
WireGuard keys, and forwarded IPv4 port, it requires some tooling to set up.
Read on for how.

### Why run VPN on a gateway?

There are a couple of ways to use a VPN. One way is to set it up on your
workstation, laptop, or mobile device, so that your traffic is encrypted on
your device, through your LAN and then the internet to the VPN service provider.
This is "end-to-end" encryption, and is the best protection a VPN can provide.
For most users, this is easy and affords plenty of protection, and for that
[PIA][] has nice desktop and mobile apps that are simple to use, but do require
installing them and setting them up. PIA is putting out apps for more and more
devices, but, unfortunately, they can't keep up with all the IoT devices, smart
home hubs, smart TVs, etc. As a result, we have to live with some unencrypted
traffic, and this segment is growing very fast in terms of number of devices and
the number of security issues arising from them.

Another way to use a VPN, available to you only if you control your network
infrastructure, is to set up your LAN's firewall to connect to the VPN service
and route all (or some selection) of the outgoing LAN traffic through the VPN.
This way, any devices on the LAN can benefit from the VPN without configuring
those devices at all. Note that this is "edge-to-edge" encryption, which is a
bit weaker since there is part of the path, the first part on your LAN, where
traffic is unencrypted. I'm okay with this, because I have physical control of
all apparatus on my LAN. If you use anyone else's wifi access point, or connect
your access point to someone else's switch, this would not be the case for you.
Stick with the VPN app. This project is for people who, like me, are okay with
this depth-for-breadth tradeoff, and who also use `systemd-networkd` on their
firewall.[^2]

Because you can, _should_ you do this? I find little downside in using a fast
[WireGuard][wireguard]-based VPN. My VPN tunneled traffic is indistinguishably
fast as untunneled traffic almost all of the time, and this suite is pretty
much hands-free for me. So is it worth the tradeoff? For me, yes, only because
the tradeoff is close to zero. I wouldn't do it if I had to make a meaningful
performance sacrifice or take on a significant administration burden.

[^1]: I have no affiliation with [PIA][] other than as a customer. My opinions
are my own, and I cannot endorse their, or any, VPN service. Caveat emptor.

[^2]: I suspect it would be trivial to adapt this tool suite to another
WireGuard-friendly network stack, especially if it is configurable with text
files. Heck, the official WireGuard client is written in go if I understand,
so you could probably, almost as easily, directly set up the tunnels with
library calls. I'm not likely to write that code though since I am happy with
`systemd-networkd` and I like having as much of my networking configuration
handled by it as possible. Check out the [Alternatives](#alternatives) though
if you have a different networking preference.

## Alternatives

| Tool                                                       | Description                                                                                                                                                             |
|------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [piawgcli](https://gitlab.com/ddb_db/piawgcli)             | Similar approach, also written in go, but without the port forwarding features, and generates a wireguard-cli configuration file instead of systemd-networkd.           |
| [Official](https://github.com/pia-foss/manual-connections) | Bash scripts that accomplish a similar goal using plain-jane networking commands, like `ip`, `wg-quick` and so on. Also has a nice list of links to other alternatives. |

Q: Why not use [miniupnp](https://github.com/miniupnp/miniupnp) (or similar) for
port forwarding?

A: PIA doesn't let you or your torrent software pick the port that gets
forwarded, they select it for you in response to your authenticated API calls.
UPnP IGD and NAT-PMP assume your ISP (in this case PIA) forwards your desired
ports to your gateway; the UPnP/NAT-PMP protocols only deal between your
gateway and the software on the LAN side. This assumption doesn't hold: PIA only
forwards traffic having a destination port they assign to you. PCP (Port Control
Protocol) could work for this in theory, if both PIA and Transmission supported
it, but currently neither do.

## Manual Install

### Tunnel Establishment

1. Install the tools. This will require a go toolchain to be installed on your system.
   The systemd units expect the binary will be installed in `/usr/local/bin`. If you
   install somewhere else, you'll have to edit the `pia-reset-tunnel@.service` and
   `pia-pf-refresh@.service` units after you install them in step 5 below.

       sudo env GOBIN=/usr/local/bin go install github.com/jdelkins/pia-tools/cmd/pia-setup-tunnel@latest
       sudo env GOBIN=/usr/local/bin go install github.com/jdelkins/pia-tools/cmd/pia-listregions@latest   # optional

2. The next steps assume you want the interface named `pia` (if not, replace
   path components with your preferred interface name).

   Set up `/etc/systemd/network/pia.netdev.tmpl` and
   `/etc/systemd/network/pia.network.tmpl` template files. These
   templates use the Go package [`text/template`][text-template] to replace
   tokens with data received from [PIA][] when requesting the tunnel to be set
   up. You can use the examples in [./systemd/network](./systemd/network)
   and/or modify them to suit you.

   These examples should be pretty self-explanatory; if not, you should read
   up on [systemd-networkd][] and/or [text/template][text-template]. For info
   on what other template fields are available (though the examples demonstrate
   (I think) all of the useful ones), check out [the Tunnel struct in the `pia`
   package](./internal/pia/pia.go#L18). The template processing package includes
   [sprig][], which provides a number of additional template functions, should
   they come in handy.

       sudo install -o root -g root -m 0644 ./systemd/network/pia.net*.tmpl /etc/systemd/network/
       sudoedit /etc/systemd/network/pia.netdev.tmpl
       sudoedit /etc/systemd/network/pia.network.tmpl

3. Create a service account under which to run the service, and a cache directory.

       sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin pia
       sudo install -d -o pia -g pia -m 0750 /var/cache/pia

   The `/var/cache/pia` directory will hold `.json` files to cache information
   including your personal access tokens and WireGuard private keys. These files
   do not store your [PIA][] username or password, but should still be treated
   as private.

4. Create/edit the environment file containing your PIA credentials. You can
   copy and edit [the example file](./systemd/pia.conf). Make it readable by the
   `pia` user.

       sudo install -o root -g pia -m 0640 ./systemd/pia.conf /etc/pia.conf
       sudoedit /etc/pia.conf

5. Install [the systemd service file](./systemd/system/pia-reset-tunnel@.service)
   and [the systemd timer file](./systemd/system/pia-reset-tunnel@.timer) into
   `/etc/systemd/system`, and then enable the tunnel reset timer.

       sudo install -o root -g root -m 0644 ./systemd/system/pia-*@.{timer,service} /etc/systemd/system/
       # optional, edit for binary paths:
       sudoedit /etc/systemd/system/pia-reset-tunnel@.service
       sudoedit /etc/systemd/system/pia-pf-refresh@.service

   When you're happy with the service and timer units, activate them.

       sudo systemctl daemon-reload
       sudo systemctl enable --now pia-reset-tunnel@pia.timer

   This will reset the tunnel once a week, on Wednesdays at 03:00 by default.

6. You can activate the tunnel now.

       sudo systemctl start pia-reset-tunnel@pia.service

   You can repeat this command whenever you want to forcibly tear down and
   rebuild the tunnel with a new ip (and forwarded port, if configured).
   It is a "oneshot" service, which, on invocation follows this basic
   procedure:

    - generates a new WireGuard keypair
    - if region is "auto", determine the closest port-forward capable region
    - if a dedicated IP token is configured, looks up the dedicated IP and
      uses it instead of a region
    - registers the new WireGuard public key with PIA
    - gets the connection details from PIA based on the configured (or auto-selected) region, or the dedicated IP
    - regenerates the systemd-networkd config files using the templates
    - tears down the existing tunnel interface, if it exists
    - tells networkd to build the interface from the new config

7. Ensure it's working.

       sudo networkctl status pia
       sudo wg show pia
       curl -4 ifconfig.me

8. Adjust your network routing, if you wish, to send traffic selectively out
   of the tunnel. You're on your own here.

That's it, you should have a VPN as your IPv4 default route (assuming you
configured the `.network` file as such). Use something like `curl -4
icanhazip.com` to verify that the ip address is coming from PIA.

### Regarding VPN "leaks"

VPN leaks happen when you allow some traffic to bypass the tunnel, such as can
happen with IPv6 and DNS.

- **IPv6**. PIA doesn't provide IPv6 tunneling; it is an IPv4-only service. If
  you run an IPv4/IPv6 dual stack, any IPv6 traffic that exits via the WAN
  interface will bypass the VPN tunnel. Therefore, you may wish to add firewall
  and/or routing rules to block outgoing IPv6. The example templates don't
  enable, disable, or otherwise address IPv6 networking.

- **DNS**. Most connections start with a DNS lookup of a domain name. If
  that lookup is sent to a public DNS server via a route outside of the VPN
  tunnel, then you are leaking information about where you make connections.
  Even when DNS queries are sent through the VPN tunnel, the DNS provider
  can still log the lookup and its timing; your ISP, however, only sees
  encrypted traffic to the VPN endpoint and cannot observe the DNS contents.
  Best practice is to use the VPN-provided DNS servers, which are ostensibly
  zero-log. If you use DHCP on the LAN, you should therefore advertise PIA's
  DNS servers in option 6 (`domain-name-servers`). In practice, as of this
  writing, they are consistently `10.0.0.242` and `10.0.0.243`, but PIA could
  change them. The addresses are actually retrieved and cached in the json file
  by `pia-setup-tunnel`, and you could make use of this (in order to, e.g.,
  dynamically update your DHCP server configuration; I personally don't bother
  to do so) as the following snippet demonstrates. The example
  [`pia.network.tmpl`](./systemd/network/pia.network.tmpl) adds routes to the
  (dynamically-retrieved) DNS servers, so they should work as long as your LAN
  subnet does not overlap with `10.0.0.242/31` (for example, if you are using a
  broad `10.0.0.0/8` LAN).

  ```console
  $ jq -r '.dns_servers[]' /var/cache/pia/pia.json
  10.0.0.243
  10.0.0.242
  ```

### Enabling Port Forwarding

If you also want incoming traffic on a single TCP port and a single UDP port
(both with the same port number) to be forwarded to your VPN endpoint, then
follow the procedure below.

**Note ☞**  The following steps are *not necessary* if you are simply setting
up a tunnel on a gateway. This tool is to enable running a server behind (or
on) the gateway that accepts incoming connections to be accessible through the
VPN.

1. Install the `pia-portforward` tool.

       sudo env GOBIN=/usr/local/bin go install github.com/jdelkins/pia-tools/cmd/pia-portforward@latest

2. To do something with the forwarded port, such as telling a bittorrent
   client about it, set `PF_SCRIPT_DIR` in `/etc/pia.conf` to a
   directory of scripts to run whenever the port is set or refreshed (see
   [`pia-portforward`](#pia-portforward) below).

       sudoedit /etc/pia.conf

   Alternatively, you can parse `/var/cache/pia/pia.json` to obtain the
   assigned port. For example, to forward the port to an internal web server,
   you could:

   ```sh
   IF=pia
   PORT="$(jq -r '.PFSig.port' "/var/cache/pia/${IF}.json")"
   WEBSERVER="192.168.0.80:80"

   nft add table ip nat 2>/dev/null || true
   nft add chain ip nat pia_portforward '{ type nat hook prerouting priority -100 }' 2>/dev/null || true
   nft flush chain ip nat pia_portforward
   nft add rule ip nat pia_portforward tcp dport $PORT dnat to $WEBSERVER
   ```

3. Enable the timer to refresh the port forwarding assignment every 15 minutes

       sudo systemctl enable --now pia-pf-refresh@pia.timer

4. To enable the port forwarding now, just re-build the tunnel.

       sudo systemctl start pia-reset-tunnel@pia.service

## CLI Usage

Although it is recommended to run these tools with the help of systemd timers,
the tools are perfectly valid to use via their CLI interface. The pia-tools
repository provides two primary command-line utilities:

- `pia-setup-tunnel`
- `pia-portforward`

These are designed to work together for configuring and maintaining a PIA
WireGuard tunnel and optional port forwarding.

Additionally, `pia-listregions` simply downloads and lists the available regions
as discussed above. With `--pf` (or `-f`), only regions that support port
forwarding are listed, and with `--geo` (or `-g`), only [geo-located
regions][geo], whose servers are in another country but use IP addresses
registered to the one they are named for. `--no-pf` (`-F`) and `--no-geo`
(`-G`) invert these, listing only regions without the feature.

### pia-setup-tunnel

#### Description

`pia-setup-tunnel` creates or updates a WireGuard tunnel using the PIA API, writes
the corresponding systemd-networkd .netdev and .network files. The systemd
unit would invoke the utility, and then set up the interface for use. It is
typically, therefore, invoked from a systemd unit but may also be run manually.

The command:

- Authenticates to PIA using your username and password
- Selects a region, or looks up your dedicated IP
- Generates WireGuard keys and retrieves endpoint configuration
- Writes systemd-networkd configuration files

#### Required Inputs

Only the credential parameters are essential; defaults are provided for
everything else. Credentials may be provided via flags or environment variables:

| Parameter    | Environment Variable | Meaning              |
|--------------|----------------------|----------------------|
| `--username` | PIA_USERNAME         | PIA account username |
| `--password` | PIA_PASSWORD         | PIA account password |

#### Flags

| Flag                         | Environment Var | Default          | Meaning                                                                                                             |
|------------------------------|-----------------|------------------|---------------------------------------------------------------------------------------------------------------------|
| `--region string`            | PIA_REGION      | `auto`           | PIA region identifier (e.g., us_chicago, us_texas)                                                                  |
| `--dip-token string`         | DIP_TOKEN       | _unset_          | PIA dedicated IP token. Connects to the dedicated IP instead of a region, so `--region` is ignored.                 |
| `--username string`          | PIA_USERNAME    | _required_       | PIA account username                                                                                                |
| `--password string`          | PIA_PASSWORD    | _required_       | PIA account password                                                                                                |
| `--if-name string`           | _n/a_           | `pia`            | Interface name to create or reconfigure (e.g., v4, wg0)                                                             |
| `--netdev-file key=value,…`  | _n/a_           | _see below_      | Write a .netdev file using a key/value specification                                                                |
| `--network-file key=value,…` | _n/a_           | _see below_      | Write a .network file using a key/value specification                                                               |
| `--cache-dir`                | _n/a_           | `/var/cache/pia` | directory in which to save a json file with the tunnel parameters.                                                  |
| `--wg-binary`                | _n/a_           | `wg`             | path to the `wg` binary from wireguard-tools (look in $PATH by default)                                             |
| `--from-cache`               | _n/a_           | _unset_          | Skip accessing PIA's api, and just (re-)generate the networkd files from the json cache. Useful to debug templates. |

#### File Specification Format

Both `--netdev-file` and `--network-file` accept a comma-separated list
of key=value pairs. All of the keys are optional and will use defaults as
indicated.

| Key         | Default                                                         | Meaning                                    |
|-------------|-----------------------------------------------------------------|--------------------------------------------|
| `output=`   | `/etc/systemd/network/<ifname>.{network,netdev}`                | Path at which to save the generated file.  |
| `template=` | `/etc/systemd/network/<ifname>.{network,netdev}.tmpl`           | Path of the source template for this file. |
| `owner=`    | _invoking user_                                                 | The owner account name for the file.       |
| `group=`    | _invoking group_                                                | The group name for the file.               |
| `mode=`     | _runtime default from the environment (usually: 0666 & ~UMASK)_ | The file mode in octal (e.g. 0440)         |

Example:

`--netdev-file=output=/etc/systemd/network/pia.netdev,template=/etc/systemd/network/pia.netdev.tmpl,mode=0440,group=systemd-network`

#### Example Usage

__Minimal example using environment variables.__ This will generate
`/etc/systemd/network/pia.{netdev,network}` files using the templates
`/etc/systemd/network/pia.{netdev,network}.tmpl`. If the template files are not
found, you'll get an error. If run as non-root, the command will also fail, as
root is required to write the files to this system directory and to change the
group of the netdev file, as specified in this example. Note that, generally,
systemd-networkd will require read permission on netdev files and will fail if
the files are world-readable, for security reasons.

```sh
export PIA_USERNAME=youruser
export PIA_PASSWORD=yourpass
export PIA_REGION=us_chicago

pia-setup-tunnel --netdev-file=group=systemd-network,mode=0440
```

__Full explicit example.__ This will do the same as the above, without relying (as
much) on the defaults.

```sh
pia-setup-tunnel \
  --username youruser \
  --password yourpass \
  --region us_chicago \
  --if-name pia \
  --netdev-file=output=/etc/systemd/network/pia.netdev,template=/etc/systemd/network/pia.netdev.tmpl,owner=root,group=systemd-network,mode=0440 \
  --network-file=output=/etc/systemd/network/pia.network,template=/etc/systemd/network/pia.network.tmpl,mode=0444
```

#### Activating the tunnel

The example systemd service takes some extra steps after running `pia-setup-tunnel`
to activate the tunnel link. If you are running it on the cli, you may wish
to follow up with these steps, otherwise the tunnel will have been reconfigured,
but the changes not activated.

```sh
ip link set down dev '<ifname>' || true
ip link del '<ifname>' || true
networkctl reload
networkctl reconfigure '<ifname>'
networkctl up '<ifname>'
```

### pia-portforward

#### Description

`pia-portforward` requests and maintains a forwarded port from the active
PIA tunnel. It retrieves the assigned port and optionally runs user scripts
with it.

This command must be executed after the tunnel is active.

#### Flags

| Flag                             | Environment Var        | Default | Meaning                                                                 |
|----------------------------------|------------------------|---------|-------------------------------------------------------------------------|
| `--username string`              | PIA_USERNAME           | _none_  | Used to get a new authentication token, if expired.                     |
| `--password string`              | PIA_PASSWORD           | _none_  | ibid                                                                    |
| `--if-name string`               | _n/a_                  | `pia`   | Interface name associated with the active PIA tunnel                    |
| `--refresh`                      | _n/a_                  | _unset_ | Don't get a new port forwarding assignment, just refresh the active one |
| `--script-dir path`, `-s path`   | PF_SCRIPT_DIR          | _none_  | Directory of executables to run after the port is bound (see below)     |

#### Example Usage

__Basic port forward retrieval.__ Will obtain a forwarding port, store it in the
cache file, but do nothing further with it.

```sh
pia-portforward --if-name pia
```

__Refresh Port Forwarding Assignment.__ For reasons of practicality, this should
be called from a systemd timer or cron, but works fine from the CLI too, if you
can remember to do so every 15 minutes. Supply credentials, as the cached token
has a finite valid lifetime; with the username and password, we can grab a new
one if necessary.

```sh
export PIA_USERNAME=user
export PIA_PASSWORD=pass

pia-portforward --if-name pia --refresh
```

__Run custom scripts.__ With `--script-dir` (or `-s`), each executable file in
the directory is run, in name order, after the port is bound. Scripts are run
even if the port could not be obtained or bound, in which case `PIA_PF_PORT` is
`0`. Files are executed directly, so shell scripts need a shebang line (e.g.
`#!/bin/bash`). Hidden files, subdirectories and files without the executable
bit are skipped, so `chmod +x` a script to enable it and `chmod -x` to disable
it. Files not owned by root, or writable by group or others, are also skipped
(for symlinks, the target's owner and permissions are checked). The directory
itself must be owned by root and not writable by group or others, or no scripts
are run. The following environment variables are set for scripts:

| Variable               | Meaning                                                                             |
|------------------------|-------------------------------------------------------------------------------------|
| `PIA_PF_PORT`          | The forwarded port; `0` if port forwarding failed                                   |
| `PIA_PF_PORT_PREVIOUS` | The forwarded port from the previous run; empty if none (e.g. after a tunnel reset) |
| `PIA_PF_PORT_CHANGED`  | `1` if the port changed since the previous run; empty if unchanged                  |
| `PIA_PF_EXPIRY`        | Port assignment expiry (RFC 3339)                                                   |
| `PIA_INTERFACE`        | WireGuard interface name                                                            |
| `PIA_STATUS`           | Status of the last PIA API call; `ERROR` if port forwarding failed                  |
| `PIA_MESSAGE`          | Message from the last PIA API call                                                  |
| `PIA_REGION_ID`        | Region identifier                                                                   |
| `PIA_REGION_NAME`      | Region display name                                                                 |
| `PIA_SERVER_PORT`      | Server WireGuard port                                                               |
| `PIA_SERVER_IP`        | Server endpoint IP                                                                  |
| `PIA_SERVER_VIP`       | Server virtual IP inside the tunnel                                                 |
| `PIA_PEER_IP`          | Our IP inside the tunnel                                                            |
| `PIA_DNS_SERVERS`      | Space-separated list of PIA DNS servers                                             |
| `PIA_TOKEN_EXPIRY`     | Token expiry (RFC 3339)                                                             |
| `PIA_JSON`             | The full tunnel description as a JSON object, excluding keys and secrets            |

If a script fails to run or exits with a non-zero status, the failure is logged
and `pia-portforward` carries on with the remaining scripts. Once they have all
run, `pia-portforward` exits with a non-zero status if port forwarding or any
script failed. After a failure, `--refresh` requests a new port, as there is no
longer one to refresh.

```sh
pia-portforward --if-name pia --script-dir /usr/local/lib/pia-pf
```

[systemd-networkd]: https://www.freedesktop.org/software/systemd/man/systemd.network.html
[wireguard]: https://www.wireguard.com/
[PIA]: https://www.privateinternetaccess.com/
[geo]: https://www.privateinternetaccess.com/blog/private-internet-access-to-expand-network-with-30-geo-located-regions/
[sprig]: http://masterminds.github.io/sprig/
[text-template]: https://pkg.go.dev/text/template
