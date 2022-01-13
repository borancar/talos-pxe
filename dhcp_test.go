package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getAvailableRange(t *testing.T) {
	tests := map[string]struct {
		cidr  string
		want  string
		want1 string
	}{
		"default case": {
			"192.168.123.1/24", "192.168.123.2", "192.168.123.254",
		},
		"network 8": {
			"10.0.0.1/8", "10.0.0.2", "10.255.255.254",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			netIp, ipNet, err := net.ParseCIDR(tt.cidr)
			require.Nil(t, err)

			got, got1 := getAvailableRange(*ipNet, netIp)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.want1, got1)
		})
	}
}
