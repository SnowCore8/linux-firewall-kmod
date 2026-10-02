package analysis

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

type NetworkDistribution struct {
	Subnet           string   `json:"subnet"`
	UniqueIPs        int      `json:"unique_ips"`
	TotalBans        int      `json:"total_bans"`
	LastBannedAt     int64    `json:"last_banned_at"`
	RepresentativeIP string   `json:"representative_ip"`
	IPs              []string `json:"ips"`
}

func AnalyzeNetworkDistribution(db *persist.DB, days int, limit int) ([]NetworkDistribution, error) {
	if days <= 0 {
		days = 7
	}
	if limit <= 0 {
		limit = 50
	}

	events, err := db.GetBanEvents(10000)
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	subnetData := make(map[string]*struct {
		ips        map[string]int
		lastBanned int64
	})

	for _, e := range events {
		if e.BannedAt < cutoff {
			continue
		}

		subnet, err := getSubnet(e.IP)
		if err != nil {
			continue
		}

		if subnetData[subnet] == nil {
			subnetData[subnet] = &struct {
				ips        map[string]int
				lastBanned int64
			}{
				ips: make(map[string]int),
			}
		}

		data := subnetData[subnet]
		data.ips[e.IP]++
		if e.BannedAt > data.lastBanned {
			data.lastBanned = e.BannedAt
		}
	}

	var distributions []NetworkDistribution
	for subnet, data := range subnetData {
		var totalBans int
		var representativeIP string
		var maxCount int
		var ips []string

		for ip, count := range data.ips {
			totalBans += count
			ips = append(ips, ip)
			if count > maxCount {
				maxCount = count
				representativeIP = ip
			}
		}

		distributions = append(distributions, NetworkDistribution{
			Subnet:           subnet,
			UniqueIPs:        len(data.ips),
			TotalBans:        totalBans,
			LastBannedAt:     data.lastBanned,
			RepresentativeIP: representativeIP,
			IPs:              ips,
		})
	}

	sort.Slice(distributions, func(i, j int) bool {
		return distributions[i].TotalBans > distributions[j].TotalBans
	})

	if len(distributions) > limit {
		distributions = distributions[:limit]
	}

	return distributions, nil
}

func getSubnet(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}

	if ip.To4() != nil {
		parts := strings.Split(ipStr, ".")
		if len(parts) != 4 {
			return "", fmt.Errorf("invalid IPv4: %s", ipStr)
		}
		return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2]), nil
	}

	return fmt.Sprintf("%s/48", ip.Mask(net.CIDRMask(48, 128)).String()), nil
}
