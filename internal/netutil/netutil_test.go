package netutil_test

import (
	"testing"

	"github.com/webstudiobond/crowdsec-cloudflare-list-bouncer/internal/netutil"
)

func TestNormalizeSingleIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  string
		want   string
		wantOk bool
	}{
		{
			name:   "valid ipv4 address",
			value:  "192.0.2.1",
			want:   "192.0.2.1",
			wantOk: true,
		},
		{
			name:   "valid ipv6 address with normalization to 64",
			value:  "2001:db8:abcd:1234::1",
			want:   "2001:db8:abcd:1234::/64",
			wantOk: true,
		},
		{
			name:   "invalid ip format",
			value:  "999.999.999.999",
			want:   "",
			wantOk: false,
		},
		{
			name:   "empty ip string",
			value:  "   ",
			want:   "",
			wantOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := netutil.NormalizeIP("Ip", tc.value)
			if ok != tc.wantOk {
				t.Fatalf("NormalizeIP(Ip, %q) ok = %v, wantOk = %v", tc.value, ok, tc.wantOk)
			}
			if got != tc.want {
				t.Errorf("NormalizeIP(Ip, %q) = %q, want = %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestNormalizeCIDR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  string
		want   string
		wantOk bool
	}{
		{
			name:   "valid ipv4 24 block",
			value:  "192.0.2.10/24",
			want:   "192.0.2.0/24",
			wantOk: true,
		},
		{
			name:   "valid ipv4 16 block boundary",
			value:  "198.51.100.5/16",
			want:   "198.51.0.0/16",
			wantOk: true,
		},
		{
			name:   "disallowed wide ipv4 8 block",
			value:  "10.0.0.0/8",
			want:   "",
			wantOk: false,
		},
		{
			name:   "valid ipv6 64 block",
			value:  "2001:db8:1234:5678::5/64",
			want:   "2001:db8:1234:5678::/64",
			wantOk: true,
		},
		{
			name:   "valid ipv6 48 block boundary",
			value:  "2001:db8:1234::/48",
			want:   "2001:db8:1234::/48",
			wantOk: true,
		},
		{
			name:   "disallowed wide ipv6 32 block",
			value:  "2001:db8::/32",
			want:   "",
			wantOk: false,
		},
		{
			name:   "malformed cidr string",
			value:  "invalid/prefix",
			want:   "",
			wantOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := netutil.NormalizeIP("Range", tc.value)
			if ok != tc.wantOk {
				t.Fatalf("NormalizeIP(Range, %q) ok = %v, wantOk = %v", tc.value, ok, tc.wantOk)
			}
			if got != tc.want {
				t.Errorf("NormalizeIP(Range, %q) = %q, want = %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestNormalizeUnsupportedScopes(t *testing.T) {
	t.Parallel()

	unsupportedScopes := []string{"Country", "AS", "User", "Session"}
	for _, scope := range unsupportedScopes {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()

			got, ok := netutil.NormalizeIP(scope, "192.0.2.1")
			if ok {
				t.Errorf("NormalizeIP(%q) expected ok = false, got true with value %q", scope, got)
			}
		})
	}
}
