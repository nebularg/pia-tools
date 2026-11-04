package pia

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

type Region struct {
	Id          string              `json:"id"`
	Name        string              `json:"name"`
	PortForward bool                `json:"port_forward"`
	Servers     map[string][]Server `json:"servers"`
	Latency     time.Duration
}

func (self *Region) server(typ string) *Server {
	s, ok := self.Servers[typ]
	if !ok {
		return nil
	}
	return &s[0]
}

func (self *Region) WgServer() *Server {
	return self.server("wg")
}

func (self *Region) MetaServer() *Server {
	return self.server("meta")
}

func (self *Region) HasWg() bool {
	return self.WgServer() != nil
}

// setLatency sets Latency to the time taken to open a TCP connection to the
// region's meta server, as PIA's manual-connections scripts measure it, or to 0
// if the server could not be reached within a second.
func (self *Region) setLatency() {
	self.Latency = time.Duration(0)
	meta := self.MetaServer()
	if meta == nil {
		return
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(meta.Ip, "443"), 1*time.Second)
	if err != nil {
		return
	}
	self.Latency = time.Since(start)
	conn.Close()
}

func RegionsWithLatency() ([]Region, error) {
	regions, err := Regions()
	if err != nil {
		return nil, err
	}

	// parallelize the connections, obviously, or we'll be here all day
	var done sync.WaitGroup
	for i := range regions {
		r := &regions[i]
		done.Add(1)
		go func(done *sync.WaitGroup) {
			r.setLatency()
			done.Done()
		}(&done)
	}
	done.Wait()

	// sort by increasing latency
	sort.Slice(regions, func(i, j int) bool {
		if regions[i].Latency == 0 {
			return false
		}
		if regions[j].Latency == 0 {
			return true
		}
		return regions[i].Latency < regions[j].Latency
	})
	return regions, nil
}

func Regions() ([]Region, error) {
	const pia_url_servers = "https://serverlist.piaservers.net/vpninfo/servers/v6"
	resp, err := http.Get(pia_url_servers)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not get server list: %s", resp.Status)
	}

	// the JSON is followed by a newline and a signature, which Decode leaves
	// unread
	var _r struct {
		Regions []Region `json:"regions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&_r); err != nil {
		return nil, err
	}
	return _r.Regions, nil
}

func FindRegion(id string) (*Region, error) {
	regions, err := Regions()
	if err != nil {
		return nil, err
	}
	for i := range regions {
		r := &regions[i]
		if r.Id == id {
			if r.WgServer() == nil {
				return nil, fmt.Errorf("Region %s (%s) was found but does not have a WireGuard server", r.Id, r.Name)
			}
			r.setLatency()
			if r.Latency == 0 {
				fmt.Fprintf(os.Stderr, "Warning: region %s (%s) is not currently reachable\n", r.Id, r.Name)
			}
			return r, nil
		}
	}
	return nil, fmt.Errorf("Could not find region %s", id)
}
