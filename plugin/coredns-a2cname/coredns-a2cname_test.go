package coredns_a2cname

import "testing"

func TestMatchesZone(t *testing.T) {
	tests := []struct {
		zones   []string
		qname   string
		shouldMatch bool
		name    string
	}{
		// Wildcard zone tests
		{[]string{"*.example.com."}, "foo.example.com.", true, "wildcard subdomain match"},
		{[]string{"*.example.com."}, "bar.example.com.", true, "wildcard subdomain match 2"},
		{[]string{"*.example.com."}, "example.com.", false, "wildcard should not match base zone"},
		{[]string{"*.example.com."}, "baz.foo.example.com.", true, "wildcard deeper subdomain"},
		{[]string{"*.example.com."}, "other.com.", false, "wildcard no match"},
		// Non-wildcard zone tests
		{[]string{"example.com."}, "foo.example.com.", true, "non-wildcard subdomain match"},
		{[]string{"example.com."}, "example.com.", true, "non-wildcard base zone match"},
		{[]string{"example.com."}, "other.com.", false, "non-wildcard no match"},
		// Mixed zones
		{[]string{"*.example.com.", "other.com."}, "foo.example.com.", true, "wildcard in mixed"},
		{[]string{"*.example.com.", "other.com."}, "other.com.", true, "non-wildcard in mixed"},
		{[]string{"*.example.com.", "other.com."}, "baz.other.com.", true, "non-wildcard subdomain in mixed"},
	}

	for _, test := range tests {
		i := &IpToCname{Zones: test.zones}
		matched := i.matchesZone(test.qname)
		if matched != test.shouldMatch {
			t.Errorf("%s: zones=%v, qname=%q, got %v, want %v", test.name, test.zones, test.qname, matched, test.shouldMatch)
		}
	}
} 