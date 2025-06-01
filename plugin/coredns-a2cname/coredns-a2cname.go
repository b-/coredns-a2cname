package coredns_a2cname

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("coredns-a2cname")

// IpToCname implements a plugin that resolves A records and returns CNAME records
// based on IP address transformation
type IpToCname struct {
	Next         plugin.Handler
	Zones        []string
	TargetSuffix string
	Upstream     string
}

// ServeDNS implements the plugin.Handler interface
func (i *IpToCname) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// Only handle A record queries
	if len(r.Question) == 0 || r.Question[0].Qtype != dns.TypeA {
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	qname := r.Question[0].Name

	// Check if the query matches our zones
	if !i.matchesZone(qname) {
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	log.Debugf("Processing query for: %s", qname)

	// Resolve the A record upstream
	ip, err := i.resolveUpstream(qname)
	if err != nil {
		log.Errorf("Failed to resolve %s: %v", qname, err)
		return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
	}

	// Transform IP to target domain
	targetDomain := i.transformIP(ip)
	log.Debugf("Transformed %s (%s) -> %s", qname, ip, targetDomain)

	// Create CNAME response
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	cname := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Target: targetDomain,
	}

	resp.Answer = append(resp.Answer, cname)
	w.WriteMsg(resp)
	return dns.RcodeSuccess, nil
}

// Name returns the plugin name
func (i *IpToCname) Name() string { return "coredns-a2cname" }

// matchesZone checks if the query name matches any of our configured zones
func (i *IpToCname) matchesZone(qname string) bool {
	for _, zone := range i.Zones {
		if strings.HasSuffix(strings.ToLower(qname), strings.ToLower(zone)) {
			return true
		}
	}
	return false
}

// resolveUpstream resolves the A record using upstream DNS
func (i *IpToCname) resolveUpstream(qname string) (string, error) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)

	upstream := i.Upstream

	resp, _, err := c.Exchange(m, upstream)
	if err != nil {
		return "", err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query failed with rcode: %d", resp.Rcode)
	}

	// Find the first A record
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), nil
		}
	}

	return "", fmt.Errorf("no A record found")
}

// transformIP converts an IP address to the target domain format
// Example: "10.0.123.45" -> "10-0-123-45-9.shark-perch.ts.net."
func (i *IpToCname) transformIP(ip string) string {
	// Replace dots with dashes
	transformed := strings.ReplaceAll(ip, ".", "-")

	// Add suffix
	result := fmt.Sprintf("%s%s", transformed, i.TargetSuffix)

	// Ensure it ends with a dot
	if !strings.HasSuffix(result, ".") {
		result += "."
	}

	return result
}

// init registers the plugin
func init() { plugin.Register("coredns-a2cname", setup) }

// setup is the function that gets called when the config parser encounters the plugin name
func setup(c *caddy.Controller) error {
	i, err := parseConfig(c)
	if err != nil {
		return plugin.Error("coredns-a2cname", err)
	}

	dnsserver.GetConfig(c).AddPlugin(
		func(next plugin.Handler) plugin.Handler {
			i.Next = next
			return i
		},
	)

	return nil
}

// parseConfig parses the plugin configuration
func parseConfig(c *caddy.Controller) (*IpToCname, error) {
	i := &IpToCname{
		TargetSuffix: "-via-9.shark-perch.ts.net",
		Upstream:     "100.100.100.100:53",
	}

	for c.Next() {
		args := c.RemainingArgs()

		// First argument should be the zone(s)
		if len(args) > 0 {
			i.Zones = args
		}

		for c.NextBlock() {
			switch c.Val() {
			case "target_suffix":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				i.TargetSuffix = c.Val()
			case "upstream":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				i.Upstream = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	if len(i.Zones) == 0 {
		return nil, c.Err("no zones specified")
	}

	return i, nil
}
