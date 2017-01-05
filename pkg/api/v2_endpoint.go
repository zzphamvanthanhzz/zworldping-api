package api

import (
	"fmt"

	"github.com/raintank/worldping-api/pkg/api/rbody"
	"github.com/raintank/worldping-api/pkg/log"
	"github.com/raintank/worldping-api/pkg/middleware"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/raintank/worldping-api/pkg/services/endpointdiscovery"
	"github.com/raintank/worldping-api/pkg/services/sqlstore"
)

func GetEndpoints(c *middleware.Context, query m.GetEndpointsQuery) *rbody.ApiResponse {
	query.OrgId = c.OrgId

	endpoints, err := sqlstore.GetEndpoints(&query)
	if err != nil {
		return rbody.ErrResp(err)
	}

	return rbody.OkResp("endpoints", endpoints)
}

func GetEndpointById(c *middleware.Context) *rbody.ApiResponse {
	id := c.ParamsInt64(":id")

	endpoint, err := sqlstore.GetEndpointById(c.OrgId, id)
	if err != nil {
		return rbody.ErrResp(err)
	}

	return rbody.OkResp("endpoint", endpoint)
}

func DeleteEndpoint(c *middleware.Context) *rbody.ApiResponse {
	id := c.ParamsInt64(":id")

	err := sqlstore.DeleteEndpoint(c.OrgId, id)
	if err != nil {
		return rbody.ErrResp(err)
	}

	return rbody.OkResp("endpoint", nil)
}

func AddEndpoint(c *middleware.Context, endpoint m.EndpointDTO) *rbody.ApiResponse {
	endpoint.OrgId = c.OrgId
	if endpoint.Name == "" {
		return rbody.ErrResp(m.NewValidationError("Endpoint name not set."))
	}
	for i := range endpoint.Checks {
		check := endpoint.Checks[i]
		check.OrgId = c.OrgId
		if err := check.Validate(); err != nil {
			return rbody.ErrResp(err)
		}

		err := sqlstore.ValidateCheckRoute(&check)
		if err != nil {
			return rbody.ErrResp(err)
		}
	}

	err := sqlstore.AddEndpoint(&endpoint)
	if err != nil {
		return rbody.ErrResp(err)
	}

	return rbody.OkResp("endpoint", endpoint)
}

func UpdateEndpoint(c *middleware.Context, endpoint m.EndpointDTO) *rbody.ApiResponse {
	endpoint.OrgId = c.OrgId
	if endpoint.Name == "" {
		return rbody.ErrResp(m.NewValidationError("Endpoint name not set."))
	}
	if endpoint.Id == 0 {
		return rbody.ErrResp(m.NewValidationError("Endpoint id not set."))
	}

	for i := range endpoint.Checks {
		check := endpoint.Checks[i]
		if err := check.Validate(); err != nil {
			return rbody.ErrResp(err)
		}
	}

	err := sqlstore.UpdateEndpoint(&endpoint)
	if err != nil {
		return rbody.ErrResp(err)
	}

	return rbody.OkResp("endpoint", endpoint)
}
func getDefaultChecks(hostname string) (*m.EndpointDTO, error) {
	endpoint, err := endpointdiscovery.NewEndpoint(hostname)
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
		Enabled: false,
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
		Enabled: false,
	}
	pingCheck := m.Check{
		Type:      "ping",
		Frequency: 10,
		Settings: map[string]interface{}{
			"hostname": host,
			"timeout":  5,
		},
		Enabled: false,
	}

	checks = append(checks, httpCheck)
	checks = append(checks, httpsCheck)
	checks = append(checks, staticCheck)
	checks = append(checks, clinkCheck)
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

func DiscoverEndpoint(c *middleware.Context, cmd m.DiscoverEndpointCmd) *rbody.ApiResponse {
	log.Debug(fmt.Sprintf("Discover Endpoint checks (default) of : %s", cmd.Name))
	endpoint, err := getDefaultChecks(cmd.Name)
	if err != nil {
		return rbody.ErrResp(err)
	}

	return rbody.OkResp("endpoint", endpoint)
}
