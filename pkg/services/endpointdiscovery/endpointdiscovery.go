package endpointdiscovery

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/raintank/worldping-api/pkg/log"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/raintank/worldping-api/pkg/services/sqlstore"
)

var defaultProbes []int64

func InitEndpointDiscovery() error {
	log.Debug("Init Endpoint Discovery")
	for _, name := range []string{"VNPT_HN", "VNPT", "FPT", "VIETTEL", "THANHPV", "THANHPVWINDOW"} {
		probe, err := sqlstore.GetProbeByName(name, 1) //this is column `name` of table `probe`
		if err != nil {
			if err == m.ErrProbeNotFound {
				log.Warn("DefaultProbe %s not found.", name)
				continue
			}
			return err
		}
		defaultProbes = append(defaultProbes, probe.Id)
	}
	return nil
}

type Endpoint struct {
	Host string
	IsIP bool
	URL  *url.URL
}

func NewEndpoint(hostname string) (*Endpoint, error) {
	e := &Endpoint{Host: hostname}
	return e, nil
	// if strings.Contains(hostname, "://") {
	// 	u, err := url.Parse(hostname)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	e.Host = strings.Split(u.Host, ":")[0]
	// 	e.URL = u
	// }
	// e.Host = strings.ToLower(e.Host)

	// if net.ParseIP(e.Host) != nil {
	// 	// the parsed host is an IP address.
	// 	e.IsIP = true
	// 	return e, nil
	// }

	//case tcp check:
	// if strings.Contains(hostname, ":") {
	// 	socks := strings.Split(hostname, ":")
	// 	if len(socks) == 2 {
	// 		ip := socks[0]
	// 		port := socks[1]
	// 		if _, err := strconv.Atoi(port); err == nil {
	// 			if net.ParseIP(ip) != nil {
	// 				return e, nil
	// 			}
	// 		}
	// 	}
	// }

	// addr, err := net.LookupHost(e.Host)
	// if err != nil || len(addr) < 1 {
	// 	e.Host = "www." + hostname
	// 	addr, err = net.LookupHost(e.Host)
	// 	if err != nil || len(addr) < 1 {
	// 		return nil, fmt.Errorf("failed to lookup IP of domain %s.", e.Host)
	// 	}
	// }

	// return e, nil
}

func Discover(hostname string) (*m.EndpointDTO, error) {
	checks := make([]m.Check, 0)

	endpoint, err := NewEndpoint(hostname)
	if err != nil {
		log.Error(3, "failde to parse the endpoint name %s. %s", hostname, err)
		return nil, err
	}
	var wg sync.WaitGroup
	checkChan := make(chan *m.Check)
	wg.Add(4)

	go func() {
		pingCheck, err := DiscoverPing(endpoint)
		if err == nil {
			log.Debug("discovered ping for %s", hostname)
			checkChan <- pingCheck
		}
		wg.Done()
	}()

	go func() {
		httpCheck, err := DiscoverHttp(endpoint)
		if err == nil {
			log.Debug("discovered http for %s", hostname)
			checkChan <- httpCheck
		}
		wg.Done()
	}()

	go func() {
		httpsCheck, err := DiscoverHttps(endpoint)
		if err == nil {
			log.Debug("discovered https for %s", hostname)
			checkChan <- httpsCheck
		}
		wg.Done()
	}()

	go func() {
		if !endpoint.IsIP {
			dnsCheck, err := DiscoverDNS(endpoint)
			if err == nil {
				log.Debug("discovered dns for %s", hostname)
				checkChan <- dnsCheck
			}
		}
		wg.Done()
	}()

	go func() {
		wg.Wait()
		close(checkChan)
	}()

	for c := range checkChan {
		c.HealthSettings = &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		}
		c.Route = &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		}
		checks = append(checks, *c)
	}

	resp := m.EndpointDTO{
		Name:   endpoint.Host,
		Checks: checks,
	}

	return &resp, nil

}

func GetDefaultChecks(hostname string) (*m.EndpointDTO, error) {
	endpoint, err := NewEndpoint(hostname)
	if err != nil {
		log.Error(3, "failde to parse the endpoint name %s. %s", hostname, err)
		return nil, err
	}

	checks := make([]m.Check, 0)
	path := "/"
	host := hostname
	if endpoint.URL != nil {
		host = endpoint.URL.String()
		path = endpoint.URL.Path
	}
	httpCheck := m.Check{
		Type:      "http",
		Frequency: 60,
		Settings: map[string]interface{}{
			"host":    host,
			"port":    80,
			"path":    path,
			"method":  "GET",
			"headers": "User-Agent: Mozilla/5.0\nAccept-Encoding: gzip\n",
			"timeout": 5,
			"getall":  true,
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: true,
	}

	httpsCheck := m.Check{
		Type:      "https",
		Frequency: 60,
		Settings: map[string]interface{}{
			"host":    host,
			"port":    443,
			"path":    path,
			"method":  "GET",
			"headers": "User-Agent: Mozilla/5.0\nAccept-Encoding: gzip\n",
			"timeout": 5,
			"getall":  true,
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: true,
	}

	staticCheck := m.Check{
		Type:      "static",
		Frequency: 60,
		Settings: map[string]interface{}{
			"host":    host,
			"method":  "GET",
			"headers": "User-Agent: Mozilla/5.0\nAccept-Encoding: gzip\n",
			"timeout": 5,
			"total":   5,
			"getall":  true,
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: true,
	}

	clinkCheck := m.Check{
		Type:      "clink",
		Frequency: 1800,
		Settings: map[string]interface{}{
			"host":    host,
			"method":  "GET",
			"headers": "User-Agent: Mozilla/5.0\nAccept-Encoding: gzip\n",
			"timeout": 5,
			"total":   5,
			"getall":  true,
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: false,
	}

	cdnintegrityCheck := m.Check{
		Type:      "cdnintegrity",
		Frequency: 1800,
		Settings: map[string]interface{}{
			"host":      host,
			"headers":   "User-Agent: Mozilla/5.0\nAccept-Encoding: gzip\n",
			"numfile":   5,
			"chunksize": 3145728,
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: false,
	}
	tcpCheck := m.Check{
		Type:      "tcp",
		Frequency: 1800,
		Settings: map[string]interface{}{
			"host": host,
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: false,
	}

	//Default disable:
	dnsCheck := m.Check{
		Type:      "dns",
		Frequency: 60,
		Settings: map[string]interface{}{
			"name":     "",
			"type":     "",
			"port":     53,
			"server":   "",
			"timeout":  5,
			"protocol": "udp",
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: false,
	}
	pingCheck := m.Check{
		Type:      "ping",
		Frequency: 10,
		Settings: map[string]interface{}{
			"hostname": host,
			"timeout":  5,
		},
		Route: &m.CheckRoute{
			Type:   m.RouteByIds,
			Config: map[string]interface{}{"ids": defaultProbes},
		},
		HealthSettings: &m.CheckHealthSettings{
			NumProbes: 1,
			Steps:     1,
		},
		Enabled: false,
	}

	checks = append(checks, httpCheck)
	checks = append(checks, httpsCheck)
	checks = append(checks, staticCheck)
	checks = append(checks, clinkCheck)
	checks = append(checks, tcpCheck)
	checks = append(checks, cdnintegrityCheck)
	//Default disable:
	checks = append(checks, dnsCheck)
	checks = append(checks, pingCheck)

	resp := m.EndpointDTO{
		Name:   hostname,
		Checks: checks,
	}

	return &resp, nil
}

func DiscoverPing(endpoint *Endpoint) (*m.Check, error) {
	err := exec.Command("ping", "-c 3", "-W 1", "-q", endpoint.Host).Run()
	if err != nil {
		return nil, errors.New("host unreachable")
	}

	return &m.Check{
		Type:      "ping",
		Frequency: 60,
		Settings: map[string]interface{}{
			"hostname": endpoint.Host,
			"timeout":  5,
		},
		Enabled: true,
	}, nil
}

func DiscoverHttp(endpoint *Endpoint) (*m.Check, error) {
	host := endpoint.Host
	path := "/"
	if endpoint.URL != nil {
		if endpoint.URL.Scheme == "http" {
			host = endpoint.URL.Host
		}
		path = endpoint.URL.Path
	}
	resp, err := http.Head(fmt.Sprintf("http://%s%s", host, path))
	if err != nil {
		return nil, err
	}

	requestUrl := resp.Request.URL
	if requestUrl.Scheme != "http" {
		return nil, errors.New("HTTP redirects to HTTPS")
	}

	hostParts := strings.Split(requestUrl.Host, ":")
	varHost := hostParts[0]
	varPort := int64(80)
	if len(hostParts) > 1 {
		varPort, _ = strconv.ParseInt(hostParts[1], 10, 32)
	}

	return &m.Check{
		Type:      "http",
		Frequency: 120,
		Settings: map[string]interface{}{
			"host":    varHost,
			"port":    varPort,
			"path":    requestUrl.Path,
			"method":  "GET",
			"headers": "User-Agent: worldping-api\nAccept-Encoding: gzip\n",
			"timeout": 5,
		},
		Enabled: true,
	}, nil
}

func DiscoverHttps(endpoint *Endpoint) (*m.Check, error) {
	host := endpoint.Host
	path := "/"
	if endpoint.URL != nil {
		if endpoint.URL.Scheme == "https" {
			host = endpoint.URL.Host
		}
		path = endpoint.URL.Path
	}
	resp, err := http.Head(fmt.Sprintf("https://%s%s", host, path))
	if err != nil {
		return nil, err
	}
	requestUrl := resp.Request.URL

	hostParts := strings.Split(requestUrl.Host, ":")
	varHost := hostParts[0]
	varPort := int64(443)
	if len(hostParts) > 1 {
		varPort, _ = strconv.ParseInt(hostParts[1], 10, 32)
	}

	return &m.Check{
		Type:      "https",
		Frequency: 120,
		Settings: map[string]interface{}{
			"host":         varHost,
			"port":         varPort,
			"path":         requestUrl.Path,
			"method":       "GET",
			"headers":      "User-Agent: worldping-api\nAccept-Encoding: gzip\n",
			"timeout":      5,
			"validateCert": true,
		},
		Enabled: true,
	}, nil
}

func DiscoverDNS(endpoint *Endpoint) (*m.Check, error) {
	domain := endpoint.Host
	recordType := "A"
	recordName := domain
	server := "8.8.8.8"
	for {
		nameservers, err := net.LookupNS(domain)
		if err != nil || len(nameservers) < 1 {
			parts := strings.Split(domain, ".")
			if len(parts) < 2 {
				break
			}
			domain = strings.Join(parts[1:], ".")
		} else {
			servers := make([]string, len(nameservers))
			for i, ns := range nameservers {
				s := strings.TrimSuffix(ns.Host, ".")
				servers[i] = s
			}
			server = strings.Join(servers, ",")
			break
		}
	}

	return &m.Check{
		Type:      "dns",
		Frequency: 120,
		Settings: map[string]interface{}{
			"name":     recordName,
			"type":     recordType,
			"port":     53,
			"server":   server,
			"timeout":  5,
			"protocol": "udp",
		},
		Enabled: true,
	}, nil
}
