package pia

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type DedicatedIP struct {
	Ip     string    `json:"ip"`
	Cn     string    `json:"cn"`
	Id     string    `json:"id"`
	Expiry time.Time `json:"expiry"`
	// KeyHostname is the username with which to register a WireGuard key
	// with the dedicated IP's server. It contains the dedicated IP token.
	KeyHostname string `json:"key_hostname"`
}

// Region returns a region whose only server is the dedicated IP. As in PIA's
// manual-connections scripts, dedicated IPs in the US are taken to not support
// port forwarding.
func (dip *DedicatedIP) Region() *Region {
	return &Region{
		Id:          dip.Id,
		Name:        "Dedicated IP " + dip.Ip,
		PortForward: !strings.HasPrefix(dip.Id, "us_"),
		Servers:     map[string][]Server{"wg": {{Ip: dip.Ip, Cn: dip.Cn}}},
	}
}

// FindDedicatedIP looks up the dedicated IP identified by dipToken, which must
// be active.
func FindDedicatedIP(token Token, dipToken string) (*DedicatedIP, error) {
	body, err := json.Marshal(map[string][]string{"tokens": {dipToken}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", "https://www.privateinternetaccess.com/api/client/v2/dedicated_ip", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Token "+token.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not get dedicated IP: %s", resp.Status)
	}

	var dips []struct {
		Status string `json:"status"`
		Ip     string `json:"ip"`
		Cn     string `json:"cn"`
		Id     string `json:"id"`
		Expire int64  `json:"dip_expire"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dips); err != nil {
		return nil, err
	}
	if len(dips) == 0 {
		return nil, fmt.Errorf("could not get dedicated IP: empty response")
	}
	if dips[0].Status != "active" {
		return nil, fmt.Errorf("dedicated IP token is not active: status=\"%s\"", dips[0].Status)
	}
	return &DedicatedIP{
		Ip:          dips[0].Ip,
		Cn:          dips[0].Cn,
		Id:          dips[0].Id,
		Expiry:      time.Unix(dips[0].Expire, 0),
		KeyHostname: "dedicated_ip_" + dipToken,
	}, nil
}
