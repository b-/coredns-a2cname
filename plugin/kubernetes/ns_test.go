package kubernetes

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/kubernetes/object"

	"github.com/miekg/dns"
	api "k8s.io/api/core/v1"
)

type APIConnTest struct{}

func (APIConnTest) HasSynced() bool                                  { return true }
func (APIConnTest) Run()                                             {}
func (APIConnTest) Stop() error                                      { return nil }
func (APIConnTest) PodIndex(string) []*object.Pod                    { return nil }
func (APIConnTest) SvcIndexReverse(string) []*object.Service         { return nil }
func (APIConnTest) SvcExtIndexReverse(string) []*object.Service      { return nil }
func (APIConnTest) ServiceImportList() []*object.ServiceImport       { return nil }
func (APIConnTest) SvcImportIndex(string) []*object.ServiceImport    { return nil }
func (APIConnTest) EpIndex(string) []*object.Endpoints               { return nil }
func (APIConnTest) McEpIndex(string) []*object.MultiClusterEndpoints { return nil }
func (APIConnTest) EndpointsList() []*object.Endpoints               { return nil }
func (APIConnTest) Modified(ModifiedMode) int64                      { return 0 }

func (a APIConnTest) SvcIndex(s string) []*object.Service {
	switch s {
	case "dns-service.kube-system":
		return []*object.Service{a.ServiceList()[0]}
	case "hdls-dns-service.kube-system":
		return []*object.Service{a.ServiceList()[1]}
	case "dns6-service.kube-system":
		return []*object.Service{a.ServiceList()[2]}
	}
	return nil
}

var svcs = []*object.Service{
	{
		Name:       "dns-service",
		Namespace:  "kube-system",
		ClusterIPs: []string{"10.0.0.111"},
	},
	{
		Name:       "hdls-dns-service",
		Namespace:  "kube-system",
		ClusterIPs: []string{api.ClusterIPNone},
	},
	{
		Name:       "dns6-service",
		Namespace:  "kube-system",
		ClusterIPs: []string{"10::111"},
	},
}

func (APIConnTest) ServiceList() []*object.Service {
	return svcs
}

func (APIConnTest) EpIndexReverse(ip string) []*object.Endpoints {
	if ip != "10.244.0.20" {
		return nil
	}
	eps := []*object.Endpoints{
		{
			Name:      "dns-service-slice1",
			Namespace: "kube-system",
			Index:     object.EndpointsKey("dns-service", "kube-system"),
			Subsets: []object.EndpointSubset{
				{Addresses: []object.EndpointAddress{{IP: "10.244.0.20"}}},
			},
		},
		{
			Name:      "hdls-dns-service-slice1",
			Namespace: "kube-system",
			Index:     object.EndpointsKey("hdls-dns-service", "kube-system"),
			Subsets: []object.EndpointSubset{
				{Addresses: []object.EndpointAddress{{IP: "10.244.0.20"}}},
			},
		},
		{
			Name:      "dns6-service-slice1",
			Namespace: "kube-system",
			Index:     object.EndpointsKey("dns6-service", "kube-system"),
			Subsets: []object.EndpointSubset{
				{Addresses: []object.EndpointAddress{{IP: "10.244.0.20"}}},
			},
		},
	}
	return eps
}

func (APIConnTest) GetNodeByName(ctx context.Context, name string) (*api.Node, error) {
	return &api.Node{}, nil
}

func (APIConnTest) GetNamespaceByName(name string) (*object.Namespace, error) {
	return nil, fmt.Errorf("namespace not found")
}

func TestNsAddrs(t *testing.T) {
	k := New([]string{"inter.webs.test."})
	k.APIConn = &APIConnTest{}
	k.localIPs = []net.IP{net.ParseIP("10.244.0.20")}

	cdrs := k.nsAddrs(false, false, k.Zones[0])

	if len(cdrs) != 3 {
		t.Fatalf("Expected 3 results, got %v", len(cdrs))
	}
	cdr := cdrs[0]
	expected := "10.0.0.111"
	if cdr.(*dns.A).A.String() != expected {
		t.Errorf("Expected 1st A to be %q, got %q", expected, cdr.(*dns.A).A.String())
	}
	expected = "dns-service.kube-system.svc.inter.webs.test."
	if cdr.Header().Name != expected {
		t.Errorf("Expected 1st Header Name to be %q, got %q", expected, cdr.Header().Name)
	}
	cdr = cdrs[1]
	expected = "10.244.0.20"
	if cdr.(*dns.A).A.String() != expected {
		t.Errorf("Expected 2nd A to be %q, got %q", expected, cdr.(*dns.A).A.String())
	}
	expected = "10-244-0-20.hdls-dns-service.kube-system.svc.inter.webs.test."
	if cdr.Header().Name != expected {
		t.Errorf("Expected 2nd Header Name to be %q, got %q", expected, cdr.Header().Name)
	}
	cdr = cdrs[2]
	expected = "10::111"
	if cdr.(*dns.AAAA).AAAA.String() != expected {
		t.Errorf("Expected AAAA to be %q, got %q", expected, cdr.(*dns.A).A.String())
	}
	expected = "dns6-service.kube-system.svc.inter.webs.test."
	if cdr.Header().Name != expected {
		t.Errorf("Expected AAAA Header Name to be %q, got %q", expected, cdr.Header().Name)
	}
}

func TestNsAddrsExternalHeadless(t *testing.T) {
	k := New([]string{"example.com."})
	k.APIConn = &APIConnTest{}
	k.localIPs = []net.IP{net.ParseIP("10.244.0.20")}

	// there are only headless services
	cdrs := k.nsAddrs(true, true, k.Zones[0])

	if len(cdrs) != 1 {
		t.Fatalf("Expected 0 results, got %v", cdrs)
	}

	cdr := cdrs[0]
	expected := "10.244.0.20"
	if cdr.(*dns.A).A.String() != expected {
		t.Errorf("Expected A address to be %q, got %q", expected, cdr.(*dns.A).A.String())
	}
	expected = "10-244-0-20.hdls-dns-service.kube-system.example.com."
	if cdr.Header().Name != expected {
		t.Errorf("Expected record name to be %q, got %q", expected, cdr.Header().Name)
	}
}

func TestNsAddrsExternal(t *testing.T) {
	k := New([]string{"example.com."})
	k.APIConn = &APIConnTest{}
	k.localIPs = []net.IP{net.ParseIP("10.244.0.20")}

	// initially no services have an external IP ...
	cdrs := k.nsAddrs(true, false, k.Zones[0])

	if len(cdrs) != 0 {
		t.Fatalf("Expected 0 results, got %v", len(cdrs))
	}

	// Add an external IP to one of the services ...
	svcs[0].ExternalIPs = []string{"1.2.3.4"}
	cdrs = k.nsAddrs(true, false, k.Zones[0])

	if len(cdrs) != 1 {
		t.Fatalf("Expected 1 results, got %v", len(cdrs))
	}
	cdr := cdrs[0]
	expected := "1.2.3.4"
	if cdr.(*dns.A).A.String() != expected {
		t.Errorf("Expected A address to be %q, got %q", expected, cdr.(*dns.A).A.String())
	}
	expected = "dns-service.kube-system.example.com."
	if cdr.Header().Name != expected {
		t.Errorf("Expected record name to be %q, got %q", expected, cdr.Header().Name)
	}
}

func TestNsAddrsExternalWithPreexistingExternalIP(t *testing.T) {
	k := New([]string{"example.com."})
	k.APIConn = &APIConnTest{}
	k.localIPs = []net.IP{net.ParseIP("10.244.0.20")}

	svcs[0].ExternalIPs = []string{"1.2.3.4"}

	// initially no services have an external IP ...
	cdrs := k.nsAddrs(true, false, k.Zones[0])

	if len(cdrs) != 1 {
		t.Fatalf("Expected 1 results, got %v", len(cdrs))
	}

	if len(cdrs) != 1 {
		t.Fatalf("Expected 1 results, got %v", len(cdrs))
	}
	cdr := cdrs[0]
	expected := "1.2.3.4"
	if cdr.(*dns.A).A.String() != expected {
		t.Errorf("Expected A address to be %q, got %q", expected, cdr.(*dns.A).A.String())
	}
	expected = "dns-service.kube-system.example.com."
	if cdr.Header().Name != expected {
		t.Errorf("Expected record name to be %q, got %q", expected, cdr.Header().Name)
	}
}
