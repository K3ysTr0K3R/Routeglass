package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

var (
	flagIP        = flag.String("ip", "", "Single IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-192.168.1.10)")
	flagFile      = flag.String("f", "", "File containing targets (one per line, same formats as -ip)")
	flagThreads   = flag.Int("t", 50, "Number of concurrent workers")
	flagOutput    = flag.String("o", "", "Output file to write results")
	flagAppend    = flag.Bool("append", false, "Append to output file (if -o is given)")
	flagUserAgent = flag.String("user-agent", "", "Custom User-Agent (if empty, random real browser UA)")
	flagPorts     = flag.String("ports", "80", "Comma-separated ports to scan")
)

var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
}

type AdvancedRule struct {
	Vendor    string
	Product   string
	Path      string
	Condition string
	MD5       string
}

type Rule struct {
	Vendor    string
	Product   string
	Path      string
	Condition string
	MD5       string
}

var advancedRules = []AdvancedRule{
	{Vendor: "Cisco", Product: "Cisco IOS Router", Path: "/", Condition: "title=`Cisco Systems`||title=`Cisco Configuration`||title=`Cisco Router`"},
	{Vendor: "Cisco", Product: "Cisco IOS Router", Path: "/", Condition: "body=`Cisco Systems`&&body=`All rights reserved`"},
	{Vendor: "Cisco", Product: "Cisco IOS Router", Path: "/", Condition: "header=`Server: cisco-IOS`"},
	{Vendor: "Cisco", Product: "Cisco IOS Router", Path: "/favicon.ico", MD5: "e9f4b6c1e3b5f1d5f6b7c8d9e0f1a2b3"},
	{Vendor: "Cisco", Product: "Cisco RV Series", Path: "/", Condition: "title=`Cisco RV`||title=`RV Series`"},
	{Vendor: "Cisco", Product: "Cisco SR Series", Path: "/", Condition: "title=`Cisco SR`||title=`SR Series`"},
	{Vendor: "Cisco", Product: "Cisco Small Business", Path: "/", Condition: "title=`Small Business`&&body=`Cisco`"},
	{Vendor: "Cisco", Product: "Cisco ASA", Path: "/", Condition: "title=`Cisco ASA`||title=`ASA`"},
	{Vendor: "Cisco", Product: "Cisco Nexus", Path: "/", Condition: "title=`Cisco Nexus`||title=`Nexus`"},
	{Vendor: "Cisco", Product: "Cisco Meraki", Path: "/", Condition: "title=`Meraki`||header=`Meraki`"},
	{Vendor: "Cisco", Product: "Cisco Wireless", Path: "/", Condition: "title=`Cisco Wireless`"},
	{Vendor: "Cisco", Product: "Cisco Router (any)", Path: "/", Condition: "title=~`(?i)cisco\\s+[a-z0-9-]+`"},
	{Vendor: "Cisco", Product: "Cisco Router (any)", Path: "/", Condition: "body=~`(?i)cisco\\s+[a-z0-9-]+`"},
	{Vendor: "Juniper", Product: "Junos OS", Path: "/", Condition: "title=`Juniper`||title=`Junos`||header=`Juniper`"},
	{Vendor: "Juniper", Product: "Juniper SRX Series", Path: "/", Condition: "title=`SRX`&&body=`Juniper`"},
	{Vendor: "Juniper", Product: "Juniper J Series", Path: "/", Condition: "title=`J-`&&body=`Juniper`"},
	{Vendor: "Juniper", Product: "Juniper MX Series", Path: "/", Condition: "title=`MX`&&body=`Juniper`"},
	{Vendor: "Juniper", Product: "Juniper EX Series", Path: "/", Condition: "title=`EX`&&body=`Juniper`"},
	{Vendor: "Juniper", Product: "Juniper PTX Series", Path: "/", Condition: "title=`PTX`&&body=`Juniper`"},
	{Vendor: "Juniper", Product: "Juniper QFX Series", Path: "/", Condition: "title=`QFX`&&body=`Juniper`"},
	{Vendor: "Juniper", Product: "Juniper ACX Series", Path: "/", Condition: "title=`ACX`&&body=`Juniper`"},
	{Vendor: "Juniper", Product: "Junos OS", Path: "/favicon.ico", MD5: "8a5b7c9d1e3f5g7h9i1j3k5m7n9p1r3t"},
	{Vendor: "Fortinet", Product: "FortiGate", Path: "/", Condition: "title=`FortiGate`||title=`FORTIGATE`||header=`FortiGate`"},
	{Vendor: "Fortinet", Product: "FortiGate", Path: "/", Condition: "body=`FortiGate`&&body=`Firewall`"},
	{Vendor: "Fortinet", Product: "FortiWifi", Path: "/", Condition: "title=`FortiWiFi`"},
	{Vendor: "Fortinet", Product: "FortiRouter", Path: "/", Condition: "title=`FortiRouter`"},
	{Vendor: "Fortinet", Product: "FortiOS", Path: "/", Condition: "title=`FortiOS`||body=`FortiOS`"},
	{Vendor: "Fortinet", Product: "FortiGate (any)", Path: "/", Condition: "title=~`(?i)fortigate\\s+[a-z0-9-]+`"},
	{Vendor: "Fortinet", Product: "FortiGate", Path: "/favicon.ico", MD5: "b2c4d6e8f0a2c4e6g8i0k2m4o6q8s0u2"},
	{Vendor: "Palo Alto", Product: "PAN-OS", Path: "/", Condition: "title=`Palo Alto`||title=`PAN-OS`||body=`Palo Alto`"},
	{Vendor: "Palo Alto", Product: "GlobalProtect", Path: "/", Condition: "title=`GlobalProtect`"},
	{Vendor: "Palo Alto", Product: "PA Series", Path: "/", Condition: "title=`PA-`&&body=`Palo Alto`"},
	{Vendor: "Palo Alto", Product: "PAN-OS", Path: "/favicon.ico", MD5: "c3d5e7f9a1b3c5d7e9f1g3h5j7k9l1m3"},
	{Vendor: "SonicWall", Product: "SonicOS", Path: "/", Condition: "title=`SonicWall`||title=`SonicOS`||body=`SonicWall`"},
	{Vendor: "SonicWall", Product: "SonicWall TZ Series", Path: "/", Condition: "title=`TZ`&&body=`SonicWall`"},
	{Vendor: "SonicWall", Product: "SonicWall NSA Series", Path: "/", Condition: "title=`NSA`&&body=`SonicWall`"},
	{Vendor: "SonicWall", Product: "SonicWall SMA", Path: "/", Condition: "title=`SMA`&&body=`SonicWall`"},
	{Vendor: "SonicWall", Product: "SonicOS", Path: "/favicon.ico", MD5: "d4e6f8g0a2b4c6d8e0f2g4h6j8k0l2m4"},
	{Vendor: "WatchGuard", Product: "Firebox", Path: "/", Condition: "title=`WatchGuard`||title=`Firebox`||header=`WatchGuard`"},
	{Vendor: "WatchGuard", Product: "Firebox", Path: "/", Condition: "body=`WatchGuard`"},
	{Vendor: "WatchGuard", Product: "WatchGuard Cloud", Path: "/", Condition: "title=`WatchGuard Cloud`"},
	{Vendor: "Aruba", Product: "ArubaOS", Path: "/", Condition: "title=`Aruba`||title=`ArubaOS`||header=`Aruba`"},
	{Vendor: "Aruba", Product: "Aruba Instant", Path: "/", Condition: "title=`Instant`&&body=`Aruba`"},
	{Vendor: "Aruba", Product: "Aruba Central", Path: "/", Condition: "title=`Central`&&body=`Aruba`"},
	{Vendor: "Ruckus", Product: "Ruckus Router", Path: "/", Condition: "title=`Ruckus`||header=`Ruckus`"},
	{Vendor: "Ruckus", Product: "ZoneDirector", Path: "/", Condition: "title=`ZoneDirector`"},
	{Vendor: "Ruckus", Product: "SmartZone", Path: "/", Condition: "title=`SmartZone`"},
	{Vendor: "Ruckus", Product: "Ruckus Unleashed", Path: "/", Condition: "title=`Unleashed`&&body=`Ruckus`"},
	{Vendor: "Extreme", Product: "ExtremeXOS", Path: "/", Condition: "title=`Extreme Networks`||title=`ExtremeXOS`||header=`Extreme`"},
	{Vendor: "Extreme", Product: "Extreme Switching", Path: "/", Condition: "title=`Summit`&&body=`Extreme`"},
	{Vendor: "Alcatel-Lucent", Product: "Alcatel Router", Path: "/", Condition: "title=`Alcatel`||body=`Alcatel`"},
	{Vendor: "Alcatel-Lucent", Product: "ISAM", Path: "/", Condition: "title=`ISAM`"},
	{Vendor: "Nokia", Product: "Nokia Router", Path: "/", Condition: "title=`Nokia`||body=`Nokia`"},
	{Vendor: "Nokia", Product: "Nokia G-Series", Path: "/", Condition: "title=`G-`&&body=`Nokia`"},
	{Vendor: "NETGEAR", Product: "NETGEAR Router", Path: "/", Condition: "title=`NETGEAR`||title=`Netgear`||header=`NETGEAR`"},
	{Vendor: "NETGEAR", Product: "Nighthawk", Path: "/", Condition: "title=`Nighthawk`"},
	{Vendor: "NETGEAR", Product: "Nighthawk Pro Gaming", Path: "/", Condition: "title=`XR`&&body=`NETGEAR`"},
	{Vendor: "NETGEAR", Product: "Orbi", Path: "/", Condition: "title=`Orbi`||title=`Orbi Pro`"},
	{Vendor: "NETGEAR", Product: "ReadyNAS", Path: "/", Condition: "title=`ReadyNAS`"},
	{Vendor: "NETGEAR", Product: "Meural", Path: "/", Condition: "title=`Meural`"},
	{Vendor: "NETGEAR", Product: "NETGEAR (model)", Path: "/", Condition: "title=~`(?i)netgear\\s+[a-z0-9]{3,6}`"},
	{Vendor: "NETGEAR", Product: "NETGEAR Router", Path: "/favicon.ico", MD5: "e5f7g9a1b3c5d7e9f1g3h5j7k9l1m3n5"},
	{Vendor: "ASUS", Product: "ASUS Router", Path: "/", Condition: "title=`ASUS`||title=`Asus`||body=`ASUS`"},
	{Vendor: "ASUS", Product: "RT Series", Path: "/", Condition: "title=`RT-`&&body=`ASUS`"},
	{Vendor: "ASUS", Product: "ROG Rapture", Path: "/", Condition: "title=`GT-`&&body=`ROG`"},
	{Vendor: "ASUS", Product: "TUF Gaming", Path: "/", Condition: "title=`TUF`&&body=`ASUS`"},
	{Vendor: "ASUS", Product: "ZenWiFi", Path: "/", Condition: "title=`ZenWiFi`"},
	{Vendor: "ASUS", Product: "AiMesh", Path: "/", Condition: "title=`AiMesh`"},
	{Vendor: "ASUS", Product: "Lyra", Path: "/", Condition: "title=`Lyra`"},
	{Vendor: "ASUS", Product: "ASUS (model)", Path: "/", Condition: "title=~`(?i)asus\\s+[a-z0-9-]{4,8}`"},
	{Vendor: "ASUS", Product: "ASUS Router", Path: "/favicon.ico", MD5: "f6g8h0a2b4c6d8e0f2g4h6j8k0l2m4n6"},
	{Vendor: "TP-Link", Product: "TP-Link Router", Path: "/", Condition: "title=`TP-Link`||title=`TP-LINK`||header=`TP-Link`"},
	{Vendor: "TP-Link", Product: "Archer Series", Path: "/", Condition: "title=`Archer`&&body=`TP-Link`"},
	{Vendor: "TP-Link", Product: "Archer AX", Path: "/", Condition: "title=`Archer AX`&&body=`TP-Link`"},
	{Vendor: "TP-Link", Product: "Archer C", Path: "/", Condition: "title=`Archer C`&&body=`TP-Link`"},
	{Vendor: "TP-Link", Product: "Deco", Path: "/", Condition: "title=`Deco`&&body=`TP-Link`"},
	{Vendor: "TP-Link", Product: "Omada", Path: "/", Condition: "title=`Omada`&&body=`TP-Link`"},
	{Vendor: "TP-Link", Product: "Kasa", Path: "/", Condition: "title=`Kasa`&&body=`TP-Link`"},
	{Vendor: "TP-Link", Product: "Tapo", Path: "/", Condition: "title=`Tapo`&&body=`TP-Link`"},
	{Vendor: "TP-Link", Product: "TP-Link (model)", Path: "/", Condition: "title=~`(?i)tp-link\\s+[a-z0-9-]{4,10}`"},
	{Vendor: "TP-Link", Product: "TP-Link Router", Path: "/favicon.ico", MD5: "g7h9a1b3c5d7e9f1g3h5j7k9l1m3n5o7"},
	{Vendor: "D-Link", Product: "D-Link Router", Path: "/", Condition: "title=`D-Link`||header=`D-Link`"},
	{Vendor: "D-Link", Product: "DIR Series", Path: "/", Condition: "title=`DIR`&&body=`D-Link`"},
	{Vendor: "D-Link", Product: "DAP Series", Path: "/", Condition: "title=`DAP`&&body=`D-Link`"},
	{Vendor: "D-Link", Product: "DI Series", Path: "/", Condition: "title=`DI`&&body=`D-Link`"},
	{Vendor: "D-Link", Product: "COVR", Path: "/", Condition: "title=`COVR`"},
	{Vendor: "D-Link", Product: "EXO", Path: "/", Condition: "title=`EXO`&&body=`D-Link`"},
	{Vendor: "D-Link", Product: "Eagle", Path: "/", Condition: "title=`Eagle`&&body=`D-Link`"},
	{Vendor: "D-Link", Product: "D-Link (model)", Path: "/", Condition: "title=~`(?i)d-link\\s+[a-z0-9-]{4,8}`"},
	{Vendor: "D-Link", Product: "D-Link Router", Path: "/favicon.ico", MD5: "h8a0b2c4d6e8f0g2h4j6k8l0m2n4o6p8"},
	{Vendor: "Linksys", Product: "Linksys Router", Path: "/", Condition: "title=`Linksys`||header=`Linksys`"},
	{Vendor: "Linksys", Product: "WRT Series", Path: "/", Condition: "title=`WRT`&&body=`Linksys`"},
	{Vendor: "Linksys", Product: "EA Series", Path: "/", Condition: "title=`EA`&&body=`Linksys`"},
	{Vendor: "Linksys", Product: "Velop", Path: "/", Condition: "title=`Velop`"},
	{Vendor: "Linksys", Product: "MX Series", Path: "/", Condition: "title=`MX`&&body=`Linksys`"},
	{Vendor: "Linksys", Product: "LAP Series", Path: "/", Condition: "title=`LAP`&&body=`Linksys`"},
	{Vendor: "Linksys", Product: "Linksys (model)", Path: "/", Condition: "title=~`(?i)linksys\\s+[a-z0-9-]{4,8}`"},
	{Vendor: "Linksys", Product: "Linksys Router", Path: "/favicon.ico", MD5: "i9b1c3d5e7f9g1h3j5k7l9m1n3o5p7q9"},
	{Vendor: "Belkin", Product: "Belkin Router", Path: "/", Condition: "title=`Belkin`||header=`Belkin`"},
	{Vendor: "Belkin", Product: "F5D Series", Path: "/", Condition: "title=`F5D`&&body=`Belkin`"},
	{Vendor: "Belkin", Product: "N150", Path: "/", Condition: "title=`N150`&&body=`Belkin`"},
	{Vendor: "Belkin", Product: "N300", Path: "/", Condition: "title=`N300`&&body=`Belkin`"},
	{Vendor: "Belkin", Product: "AC Series", Path: "/", Condition: "title=`AC`&&body=`Belkin`"},
	{Vendor: "Buffalo", Product: "Buffalo Router", Path: "/", Condition: "title=`Buffalo`||header=`Buffalo`"},
	{Vendor: "Buffalo", Product: "AirStation", Path: "/", Condition: "title=`AirStation`"},
	{Vendor: "Buffalo", Product: "WZR Series", Path: "/", Condition: "title=`WZR`&&body=`Buffalo`"},
	{Vendor: "Buffalo", Product: "WHR Series", Path: "/", Condition: "title=`WHR`&&body=`Buffalo`"},
	{Vendor: "Buffalo", Product: "WSR Series", Path: "/", Condition: "title=`WSR`&&body=`Buffalo`"},
	{Vendor: "Xiaomi", Product: "Xiaomi Router", Path: "/", Condition: "title=`Xiaomi`||body=`Xiaomi`"},
	{Vendor: "Xiaomi", Product: "Mi WiFi", Path: "/", Condition: "title=`Mi WiFi`||title=`Mi Router`"},
	{Vendor: "Xiaomi", Product: "AX Series", Path: "/", Condition: "title=`AX`&&body=`Xiaomi`"},
	{Vendor: "Xiaomi", Product: "Xiaomi (model)", Path: "/", Condition: "title=~`(?i)xiaomi\\s+[a-z0-9-]{4,8}`"},
	{Vendor: "Xiaomi", Product: "Xiaomi Router", Path: "/favicon.ico", MD5: "j0c2d4e6f8g0h2j4k6l8m0n2o4p6q8r0"},
	{Vendor: "Google", Product: "Google Wifi", Path: "/", Condition: "title=`Google Wifi`||body=`Google Wifi`"},
	{Vendor: "Google", Product: "Nest Wifi", Path: "/", Condition: "title=`Nest Wifi`||body=`Nest Wifi`"},
	{Vendor: "Google", Product: "OnHub", Path: "/", Condition: "title=`OnHub`"},
	{Vendor: "Amazon", Product: "Eero", Path: "/", Condition: "title=`Eero`||title=`eero`||header=`eero`"},
	{Vendor: "Plume", Product: "Plume Router", Path: "/", Condition: "title=`Plume`||body=`Plume`"},
	{Vendor: "MikroTik", Product: "RouterOS", Path: "/", Condition: "title=`RouterOS`||title=`MikroTik`||header=`MikroTik`"},
	{Vendor: "MikroTik", Product: "RouterBOARD", Path: "/", Condition: "title=`RouterBOARD`"},
	{Vendor: "MikroTik", Product: "SwOS", Path: "/", Condition: "title=`SwOS`||body=`SwOS`"},
	{Vendor: "MikroTik", Product: "RouterOS", Path: "/webfig/", Condition: "title=`WebFig`&&body=`MikroTik`"},
	{Vendor: "MikroTik", Product: "RouterOS", Path: "/favicon.ico", MD5: "k1d3e5f7g9h1j3k5l7m9n1o3p5q7r9s1"},
	{Vendor: "Ubiquiti", Product: "EdgeRouter", Path: "/", Condition: "title=`EdgeRouter`||title=`EdgeOS`||header=`EdgeRouter`"},
	{Vendor: "Ubiquiti", Product: "UniFi", Path: "/", Condition: "title=`UniFi`||body=`UniFi`"},
	{Vendor: "Ubiquiti", Product: "AirOS", Path: "/", Condition: "title=`AirOS`||title=`AirRouter`"},
	{Vendor: "Ubiquiti", Product: "AmpliFi", Path: "/", Condition: "title=`AmpliFi`"},
	{Vendor: "Ubiquiti", Product: "AirMax", Path: "/", Condition: "title=`AirMax`"},
	{Vendor: "Ubiquiti", Product: "AirFiber", Path: "/", Condition: "title=`AirFiber`"},
	{Vendor: "Ubiquiti", Product: "UniFi Dream", Path: "/", Condition: "title=`Dream`&&body=`UniFi`"},
	{Vendor: "Ubiquiti", Product: "UniFi Cloud", Path: "/", Condition: "title=`Cloud`&&body=`UniFi`"},
	{Vendor: "Ubiquiti", Product: "EdgeRouter", Path: "/favicon.ico", MD5: "l2e4f6g8h0j2k4l6m8n0o2p4q6r8s0t2"},
	{Vendor: "Huawei", Product: "Huawei Router", Path: "/", Condition: "title=`Huawei`||title=`HUAWEI`||header=`Huawei`"},
	{Vendor: "Huawei", Product: "EchoLife", Path: "/", Condition: "title=`EchoLife`"},
	{Vendor: "Huawei", Product: "HG Series", Path: "/", Condition: "title=`HG`&&body=`Huawei`"},
	{Vendor: "Huawei", Product: "B Series", Path: "/", Condition: "title=`B`&&body=`Huawei`"},
	{Vendor: "Huawei", Product: "Huawei (model)", Path: "/", Condition: "title=~`(?i)huawei\\s+[a-z0-9-]{4,8}`"},
	{Vendor: "Huawei", Product: "Huawei Router", Path: "/favicon.ico", MD5: "m3f5g7h9j1k3l5m7n9o1p3q5r7s9t1u3"},
	{Vendor: "ZTE", Product: "ZTE Router", Path: "/", Condition: "title=`ZTE`||body=`ZTE`"},
	{Vendor: "ZTE", Product: "ZXHN", Path: "/", Condition: "title=`ZXHN`"},
	{Vendor: "ZTE", Product: "ZXDSL", Path: "/", Condition: "title=`ZXDSL`"},
	{Vendor: "ZTE", Product: "MF Series", Path: "/", Condition: "title=`MF`&&body=`ZTE`"},
	{Vendor: "ZTE", Product: "F Series", Path: "/", Condition: "title=`F`&&body=`ZTE`"},
	{Vendor: "ZyXEL", Product: "ZyXEL Router", Path: "/", Condition: "title=`ZyXEL`||header=`ZyXEL`"},
	{Vendor: "ZyXEL", Product: "P-Series", Path: "/", Condition: "title=`P-`&&body=`ZyXEL`"},
	{Vendor: "ZyXEL", Product: "NBG Series", Path: "/", Condition: "title=`NBG`&&body=`ZyXEL`"},
	{Vendor: "ZyXEL", Product: "USG Series", Path: "/", Condition: "title=`USG`&&body=`ZyXEL`"},
	{Vendor: "ZyXEL", Product: "ATP Series", Path: "/", Condition: "title=`ATP`&&body=`ZyXEL`"},
	{Vendor: "ZyXEL", Product: "Armor", Path: "/", Condition: "title=`Armor`&&body=`ZyXEL`"},
	{Vendor: "ZyXEL", Product: "Keenetic", Path: "/", Condition: "title=`Keenetic`"},
	{Vendor: "DrayTek", Product: "DrayTek Router", Path: "/", Condition: "title=`DrayTek`||body=`DrayTek`"},
	{Vendor: "DrayTek", Product: "Vigor", Path: "/", Condition: "title=`Vigor`&&body=`DrayTek`"},
	{Vendor: "TRENDnet", Product: "TRENDnet Router", Path: "/", Condition: "title=`TRENDnet`||header=`TRENDnet`"},
	{Vendor: "TRENDnet", Product: "TEW Series", Path: "/", Condition: "title=`TEW`&&body=`TRENDnet`"},
	{Vendor: "TRENDnet", Product: "TW Series", Path: "/", Condition: "title=`TW`&&body=`TRENDnet`"},
	{Vendor: "Tenda", Product: "Tenda Router", Path: "/", Condition: "title=`Tenda`||header=`Tenda`"},
	{Vendor: "Tenda", Product: "Tenda Router", Path: "/", Condition: "title=`Tenda | login`||title=`Tenda|登录`"},
	{Vendor: "Tenda", Product: "Tenda Router", Path: "/", Condition: "title=`Tenda | Web Master`||title=`Tenda | Wireless Router`"},
	{Vendor: "Tenda", Product: "AC Series", Path: "/", Condition: "title=`AC`&&body=`Tenda`"},
	{Vendor: "Tenda", Product: "MW Series", Path: "/", Condition: "title=`MW`&&body=`Tenda`"},
	{Vendor: "Tenda", Product: "FH Series", Path: "/", Condition: "title=`FH`&&body=`Tenda`"},
	{Vendor: "Tenda", Product: "Tenda Router", Path: "/favicon.ico", MD5: "fa31b29eab2da688b11d8fafc5fc6b27"},
	{Vendor: "Netis", Product: "Netis Router", Path: "/", Condition: "title=`Netis`||body=`Netis`"},
	{Vendor: "Netis", Product: "WF Series", Path: "/", Condition: "title=`WF`&&body=`Netis`"},
	{Vendor: "Edimax", Product: "Edimax Router", Path: "/", Condition: "title=`Edimax`||header=`Edimax`"},
	{Vendor: "Edimax", Product: "BR Series", Path: "/", Condition: "title=`BR`&&body=`Edimax`"},
	{Vendor: "Edimax", Product: "EW Series", Path: "/", Condition: "title=`EW`&&body=`Edimax`"},
	{Vendor: "LevelOne", Product: "LevelOne Router", Path: "/", Condition: "title=`LevelOne`||header=`LevelOne`"},
	{Vendor: "LevelOne", Product: "WBR Series", Path: "/", Condition: "title=`WBR`&&body=`LevelOne`"},
	{Vendor: "LevelOne", Product: "FBR Series", Path: "/", Condition: "title=`FBR`&&body=`LevelOne`"},
	{Vendor: "SMC", Product: "SMC Router", Path: "/", Condition: "title=`SMC`||header=`SMC`"},
	{Vendor: "Lancom", Product: "Lancom Router", Path: "/", Condition: "title=`Lancom`||body=`Lancom`"},
	{Vendor: "Lancom", Product: "LCOS", Path: "/", Condition: "title=`LCOS`"},
	{Vendor: "Grandstream", Product: "Grandstream Router", Path: "/", Condition: "title=`Grandstream`||body=`Grandstream`"},
	{Vendor: "Grandstream", Product: "GWN Series", Path: "/", Condition: "title=`GWN`&&body=`Grandstream`"},
	{Vendor: "EnGenius", Product: "EnGenius Router", Path: "/", Condition: "title=`EnGenius`||body=`EnGenius`"},
	{Vendor: "EnGenius", Product: "ESR Series", Path: "/", Condition: "title=`ESR`&&body=`EnGenius`"},
	{Vendor: "Cambium", Product: "Cambium Router", Path: "/", Condition: "title=`Cambium`||body=`Cambium`"},
	{Vendor: "Cambium", Product: "cnPilot", Path: "/", Condition: "title=`cnPilot`"},
	{Vendor: "GL.iNet", Product: "GL.iNet Router", Path: "/", Condition: "title=`GL.iNet`||body=`GL.iNet`"},
	{Vendor: "GL.iNet", Product: "GL-Series", Path: "/", Condition: "title=`GL-`&&body=`GL.iNet`"},
	{Vendor: "Luxul", Product: "Luxul Router", Path: "/", Condition: "title=`Luxul`||body=`Luxul`"},
	{Vendor: "Luxul", Product: "XWR Series", Path: "/", Condition: "title=`XWR`&&body=`Luxul`"},
	{Vendor: "Peplink", Product: "Peplink Router", Path: "/", Condition: "title=`Peplink`||body=`Peplink`"},
	{Vendor: "Peplink", Product: "Pepwave", Path: "/", Condition: "title=`Pepwave`"},
	{Vendor: "Peplink", Product: "Balance", Path: "/", Condition: "title=`Balance`&&body=`Peplink`"},
	{Vendor: "Cradlepoint", Product: "Cradlepoint Router", Path: "/", Condition: "title=`Cradlepoint`||body=`Cradlepoint`"},
	{Vendor: "Cradlepoint", Product: "NetCloud", Path: "/", Condition: "title=`NetCloud`"},
	{Vendor: "Sierra Wireless", Product: "Sierra Router", Path: "/", Condition: "title=`Sierra`||body=`Sierra`"},
	{Vendor: "Sierra Wireless", Product: "AirLink", Path: "/", Condition: "title=`AirLink`"},
	{Vendor: "Digi", Product: "Digi Router", Path: "/", Condition: "title=`Digi`||body=`Digi`"},
	{Vendor: "Digi", Product: "Connect", Path: "/", Condition: "title=`Connect`&&body=`Digi`"},
	{Vendor: "Digi", Product: "TransPort", Path: "/", Condition: "title=`TransPort`"},
	{Vendor: "Teltonika", Product: "Teltonika Router", Path: "/", Condition: "title=`Teltonika`||body=`Teltonika`"},
	{Vendor: "Teltonika", Product: "RUT Series", Path: "/", Condition: "title=`RUT`&&body=`Teltonika`"},
	{Vendor: "Teltonika", Product: "TRB Series", Path: "/", Condition: "title=`TRB`&&body=`Teltonika`"},
	{Vendor: "Teltonika", Product: "TCR Series", Path: "/", Condition: "title=`TCR`&&body=`Teltonika`"},
	{Vendor: "Robustel", Product: "Robustel Router", Path: "/", Condition: "title=`Robustel`||body=`Robustel`"},
	{Vendor: "Robustel", Product: "R3000", Path: "/", Condition: "title=`R3000`"},
	{Vendor: "InHand", Product: "InHand Router", Path: "/", Condition: "title=`InHand`||body=`InHand`"},
	{Vendor: "Moxa", Product: "Moxa Router", Path: "/", Condition: "title=`Moxa`||body=`Moxa`"},
	{Vendor: "Actiontec", Product: "Actiontec Router", Path: "/", Condition: "title=`Actiontec`||header=`Actiontec`"},
	{Vendor: "Actiontec", Product: "MI424WR", Path: "/", Condition: "title=`MI424WR`"},
	{Vendor: "Arris", Product: "Arris Router", Path: "/", Condition: "title=`Arris`||header=`Arris`"},
	{Vendor: "Arris", Product: "Touchstone", Path: "/", Condition: "title=`Touchstone`"},
	{Vendor: "Arris", Product: "Surfboard", Path: "/", Condition: "title=`Surfboard`"},
	{Vendor: "Arris", Product: "SBG Series", Path: "/", Condition: "title=`SBG`&&body=`Arris`"},
	{Vendor: "Aztech", Product: "Aztech Router", Path: "/", Condition: "title=`Aztech`||header=`Aztech`"},
	{Vendor: "Aztech", Product: "DSL Series", Path: "/", Condition: "title=`DSL`&&body=`Aztech`"},
	{Vendor: "Aztech", Product: "HW Series", Path: "/", Condition: "title=`HW`&&body=`Aztech`"},
	{Vendor: "BEC", Product: "BEC Router", Path: "/", Condition: "title=`BEC`||body=`BEC`"},
	{Vendor: "Billion", Product: "Billion Router", Path: "/", Condition: "title=`Billion`||header=`Billion`"},
	{Vendor: "Billion", Product: "7400 Series", Path: "/", Condition: "title=`7400`&&body=`Billion`"},
	{Vendor: "Billion", Product: "7800 Series", Path: "/", Condition: "title=`7800`&&body=`Billion`"},
	{Vendor: "Calix", Product: "Calix Router", Path: "/", Condition: "title=`Calix`||body=`Calix`"},
	{Vendor: "Calix", Product: "GigaCenter", Path: "/", Condition: "title=`GigaCenter`"},
	{Vendor: "Comtrend", Product: "Comtrend Router", Path: "/", Condition: "title=`Comtrend`||header=`Comtrend`"},
	{Vendor: "Comtrend", Product: "AR Series", Path: "/", Condition: "title=`AR`&&body=`Comtrend`"},
	{Vendor: "Comtrend", Product: "VR Series", Path: "/", Condition: "title=`VR`&&body=`Comtrend`"},
	{Vendor: "Corega", Product: "Corega Router", Path: "/", Condition: "title=`Corega`||body=`Corega`"},
	{Vendor: "FiberHome", Product: "FiberHome Router", Path: "/", Condition: "title=`FiberHome`||body=`FiberHome`"},
	{Vendor: "Hitron", Product: "Hitron Router", Path: "/", Condition: "title=`Hitron`||header=`Hitron`"},
	{Vendor: "Hitron", Product: "CGN Series", Path: "/", Condition: "title=`CGN`&&body=`Hitron`"},
	{Vendor: "Hitron", Product: "CODA Series", Path: "/", Condition: "title=`CODA`&&body=`Hitron`"},
	{Vendor: "iBall", Product: "iBall Router", Path: "/", Condition: "title=`iBall`||body=`iBall`"},
	{Vendor: "Motorola", Product: "Motorola Router", Path: "/", Condition: "title=`Motorola`||header=`Motorola`"},
	{Vendor: "Motorola", Product: "SB Series", Path: "/", Condition: "title=`SB`&&body=`Motorola`"},
	{Vendor: "Motorola", Product: "MG Series", Path: "/", Condition: "title=`MG`&&body=`Motorola`"},
	{Vendor: "NetComm", Product: "NetComm Router", Path: "/", Condition: "title=`NetComm`||header=`NetComm`"},
	{Vendor: "NetComm", Product: "NF Series", Path: "/", Condition: "title=`NF`&&body=`NetComm`"},
	{Vendor: "NetComm", Product: "NB Series", Path: "/", Condition: "title=`NB`&&body=`NetComm`"},
	{Vendor: "Nexxt", Product: "Nexxt Router", Path: "/", Condition: "title=`Nexxt`||body=`Nexxt`"},
	{Vendor: "Ovislink", Product: "Ovislink Router", Path: "/", Condition: "title=`Ovislink`||body=`Ovislink`"},
	{Vendor: "Pace", Product: "Pace Router", Path: "/", Condition: "title=`Pace`||header=`Pace`"},
	{Vendor: "Pace", Product: "5 Series", Path: "/", Condition: "title=`5`&&body=`Pace`"},
	{Vendor: "Planex", Product: "Planex Router", Path: "/", Condition: "title=`Planex`||body=`Planex`"},
	{Vendor: "Proscend", Product: "Proscend Router", Path: "/", Condition: "title=`Proscend`||body=`Proscend`"},
	{Vendor: "Repotec", Product: "Repotec Router", Path: "/", Condition: "title=`Repotec`||body=`Repotec`"},
	{Vendor: "Sagemcom", Product: "Sagemcom Router", Path: "/", Condition: "title=`Sagemcom`||header=`Sagemcom`"},
	{Vendor: "Sagemcom", Product: "Fast Series", Path: "/", Condition: "title=`Fast`||title=`F@ST`"},
	{Vendor: "Sercomm", Product: "Sercomm Router", Path: "/", Condition: "title=`Sercomm`||body=`Sercomm`"},
	{Vendor: "Siemens", Product: "Siemens Router", Path: "/", Condition: "title=`Siemens`||header=`Siemens`"},
	{Vendor: "Siemens", Product: "Gigaset", Path: "/", Condition: "title=`Gigaset`"},
	{Vendor: "Siemens", Product: "SE Series", Path: "/", Condition: "title=`SE`&&body=`Siemens`"},
	{Vendor: "Sitecom", Product: "Sitecom Router", Path: "/", Condition: "title=`Sitecom`||body=`Sitecom`"},
	{Vendor: "SparkLAN", Product: "SparkLAN Router", Path: "/", Condition: "title=`SparkLAN`||body=`SparkLAN`"},
	{Vendor: "Technicolor", Product: "Technicolor Router", Path: "/", Condition: "title=`Technicolor`||header=`Technicolor`"},
	{Vendor: "Technicolor", Product: "TG Series", Path: "/", Condition: "title=`TG`&&body=`Technicolor`"},
	{Vendor: "Technicolor", Product: "DGA Series", Path: "/", Condition: "title=`DGA`&&body=`Technicolor`"},
	{Vendor: "Technicolor", Product: "CGA Series", Path: "/", Condition: "title=`CGA`&&body=`Technicolor`"},
	{Vendor: "Thomson", Product: "Thomson Router", Path: "/", Condition: "title=`Thomson`||header=`Thomson`"},
	{Vendor: "Thomson", Product: "SpeedTouch", Path: "/", Condition: "title=`SpeedTouch`"},
	{Vendor: "Thomson", Product: "ST Series", Path: "/", Condition: "title=`ST`&&body=`Thomson`"},
	{Vendor: "Ubee", Product: "Ubee Router", Path: "/", Condition: "title=`Ubee`||header=`Ubee`"},
	{Vendor: "Ubee", Product: "DDW Series", Path: "/", Condition: "title=`DDW`&&body=`Ubee`"},
	{Vendor: "Ubee", Product: "EVW Series", Path: "/", Condition: "title=`EVW`&&body=`Ubee`"},
	{Vendor: "UPVEL", Product: "UPVEL Router", Path: "/", Condition: "title=`UPVEL`||body=`UPVEL`"},
	{Vendor: "Verifone", Product: "Verifone Router", Path: "/", Condition: "title=`Verifone`||body=`Verifone`"},
	{Vendor: "VTech", Product: "VTech Router", Path: "/", Condition: "title=`VTech`||body=`VTech`"},
	{Vendor: "Western Digital", Product: "WD Router", Path: "/", Condition: "title=`Western Digital`"},
	{Vendor: "Western Digital", Product: "My Net", Path: "/", Condition: "title=`My Net`"},
	{Vendor: "Western Digital", Product: "My Cloud", Path: "/", Condition: "title=`My Cloud`"},
	{Vendor: "XAVI", Product: "XAVI Router", Path: "/", Condition: "title=`XAVI`||body=`XAVI`"},
	{Vendor: "Z-Com", Product: "Z-Com Router", Path: "/", Condition: "title=`Z-Com`||body=`Z-Com`"},
	{Vendor: "Zhone", Product: "Zhone Router", Path: "/", Condition: "title=`Zhone`||header=`Zhone`"},
	{Vendor: "Zhone", Product: "ZX Series", Path: "/", Condition: "title=`ZX`&&body=`Zhone`"},
	{Vendor: "Comcast", Product: "Xfinity Gateway", Path: "/", Condition: "title=`Xfinity`||body=`Xfinity`"},
	{Vendor: "Comcast", Product: "Xfinity xFi", Path: "/", Condition: "title=`xFi`"},
	{Vendor: "Spectrum", Product: "Spectrum Router", Path: "/", Condition: "title=`Spectrum`||body=`Spectrum`"},
	{Vendor: "AT&T", Product: "AT&T Router", Path: "/", Condition: "title=`AT&T`||body=`AT&T`"},
	{Vendor: "AT&T", Product: "U-Verse", Path: "/", Condition: "title=`U-Verse`"},
	{Vendor: "AT&T", Product: "AT&T Fiber", Path: "/", Condition: "title=`Fiber`&&body=`AT&T`"},
	{Vendor: "AT&T", Product: "AT&T Gateway", Path: "/", Condition: "title=`Gateway`&&body=`AT&T`"},
	{Vendor: "BT", Product: "BT Router", Path: "/", Condition: "title=`BT`||body=`BT`"},
	{Vendor: "BT", Product: "Smart Hub", Path: "/", Condition: "title=`Smart Hub`||title=`Home Hub`"},
	{Vendor: "BT", Product: "Business Hub", Path: "/", Condition: "title=`Business Hub`"},
	{Vendor: "Virgin Media", Product: "Virgin Media Hub", Path: "/", Condition: "title=`Virgin Media`||body=`Virgin Media`"},
	{Vendor: "Virgin Media", Product: "Super Hub", Path: "/", Condition: "title=`Super Hub 3`||title=`Super Hub 4`"},
	{Vendor: "Sky", Product: "Sky Q Hub", Path: "/", Condition: "title=`Sky Q`||title=`Sky Hub`"},
	{Vendor: "Sky", Product: "Sky Router", Path: "/", Condition: "title=`Sky`&&body=`Sky`"},
	{Vendor: "Vodafone", Product: "Vodafone Router", Path: "/", Condition: "title=`Vodafone`||body=`Vodafone`"},
	{Vendor: "Vodafone", Product: "Vodafone Connect", Path: "/", Condition: "title=`Connect`&&body=`Vodafone`"},
	{Vendor: "Orange", Product: "Orange Router", Path: "/", Condition: "title=`Orange`||body=`Orange`"},
	{Vendor: "Orange", Product: "Livebox", Path: "/", Condition: "title=`Livebox`"},
	{Vendor: "Telstra", Product: "Telstra Router", Path: "/", Condition: "title=`Telstra`||body=`Telstra`"},
	{Vendor: "Telstra", Product: "Smart Modem", Path: "/", Condition: "title=`Smart Modem`"},
	{Vendor: "Swisscom", Product: "Swisscom Router", Path: "/", Condition: "title=`Swisscom`||body=`Swisscom`"},
	{Vendor: "KPN", Product: "KPN Router", Path: "/", Condition: "title=`KPN`||body=`KPN`"},
	{Vendor: "KPN", Product: "KPN Box", Path: "/", Condition: "title=`Box`&&body=`KPN`"},
	{Vendor: "StarHub", Product: "StarHub Router", Path: "/", Condition: "title=`StarHub`"},
	{Vendor: "Beeline", Product: "Beeline Router", Path: "/", Condition: "title=`Beeline`||body=`Beeline`"},
	{Vendor: "OpenWrt", Product: "OpenWrt", Path: "/", Condition: "title=`OpenWrt`||body=`OpenWrt`"},
	{Vendor: "OpenWrt", Product: "LEDE", Path: "/", Condition: "title=`LEDE`||body=`LEDE`"},
	{Vendor: "DD-WRT", Product: "DD-WRT", Path: "/", Condition: "title=`DD-WRT`||title=`DDWRT`||body=`DD-WRT`"},
	{Vendor: "Tomato", Product: "Tomato", Path: "/", Condition: "title=`Tomato`||body=`Tomato`"},
	{Vendor: "FreshTomato", Product: "FreshTomato", Path: "/", Condition: "title=`FreshTomato`||body=`FreshTomato`"},
	{Vendor: "pfSense", Product: "pfSense", Path: "/", Condition: "title=`pfSense`||body=`pfSense`"},
	{Vendor: "OPNsense", Product: "OPNsense", Path: "/", Condition: "title=`OPNsense`||body=`OPNsense`"},
	{Vendor: "VyOS", Product: "VyOS Router", Path: "/", Condition: "title=`VyOS`||body=`VyOS`"},
	{Vendor: "Gargoyle", Product: "Gargoyle Router", Path: "/", Condition: "title=`Gargoyle`||body=`Gargoyle`"},
}

var defaultRules []Rule

func init() {
	for _, r := range advancedRules {
		defaultRules = append(defaultRules, Rule{
			Vendor:    r.Vendor,
			Product:   r.Product,
			Path:      r.Path,
			Condition: r.Condition,
			MD5:       r.MD5,
		})
	}
}

type Result struct {
	IP      string
	Port    int
	Vendor  string
	Product string
	Details string
}

var (
	resultsChan = make(chan Result, 1000)
	doneChan    = make(chan struct{})
	wg          sync.WaitGroup
	outFile     *os.File
	totalJobs   int64
	completed   int64
	foundCount  int64

	progressMu sync.Mutex
	randSource *rand.Rand
	randMu     sync.Mutex
)

func getRandomUserAgent() string {
	randMu.Lock()
	defer randMu.Unlock()
	if len(UserAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	return UserAgents[randSource.Intn(len(UserAgents))]
}

func expandTarget(target string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, nil
	}
	if strings.Contains(target, "/") {
		_, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, err
		}
		var ips []string
		ip := ipnet.IP.Mask(ipnet.Mask)
		ones, bits := ipnet.Mask.Size()
		if ones == bits {
			return []string{ip.String()}, nil
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
		}
		if len(ips) > 2 {
			ips = ips[1 : len(ips)-1]
		}
		return ips, nil
	}
	if strings.Contains(target, "-") {
		parts := strings.SplitN(target, "-", 2)
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start == nil || end == nil {
			return nil, fmt.Errorf("invalid IP range: %s", target)
		}
		if len(start) != len(end) {
			return nil, fmt.Errorf("IP range must be same family: %s", target)
		}
		if start.To4() == nil || end.To4() == nil {
			return nil, fmt.Errorf("only IPv4 ranges are supported")
		}
		start4 := start.To4()
		end4 := end.To4()
		var ips []string
		for ip := ipToUint32(start4); ip <= ipToUint32(end4); ip++ {
			ips = append(ips, uint32ToIP(ip).String())
		}
		return ips, nil
	}
	if net.ParseIP(target) != nil {
		return []string{target}, nil
	}
	return nil, fmt.Errorf("invalid target format: %s", target)
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func loadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var all []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips, err := expandTarget(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping line %q: %v\n", line, err)
			continue
		}
		all = append(all, ips...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return all, nil
}

var httpClient *http.Client

func initHTTPClient() {
	httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func evalCondition(cond string, title, body, header, status string) bool {
	if cond == "" {
		return true
	}
	orParts := strings.Split(cond, "||")
	for _, orPart := range orParts {
		orPart = strings.TrimSpace(orPart)
		if orPart == "" {
			continue
		}
		andParts := strings.Split(orPart, "&&")
		allMatch := true
		for _, andPart := range andParts {
			andPart = strings.TrimSpace(andPart)
			if andPart == "" {
				continue
			}
			if strings.Contains(andPart, "=~") {
				field, pattern := parseRegexCondition(andPart)
				if field == "" {
					allMatch = false
					break
				}
				matched, err := regexp.MatchString(pattern, getFieldValue(field, title, body, header, status))
				if err != nil || !matched {
					allMatch = false
					break
				}
				continue
			}
			field, value := parseCondition(andPart)
			if field == "" {
				allMatch = false
				break
			}
			if !strings.Contains(getFieldValue(field, title, body, header, status), value) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return true
		}
	}
	return false
}

func parseCondition(part string) (field, value string) {
	part = strings.TrimSpace(part)
	sep := "="
	if strings.Contains(part, "!=") {
		sep = "!="
	}
	idx := strings.Index(part, sep)
	if idx == -1 {
		return "", ""
	}
	field = strings.TrimSpace(part[:idx])
	rest := strings.TrimSpace(part[idx+len(sep):])
	if strings.HasPrefix(rest, "`") && strings.HasSuffix(rest, "`") {
		rest = rest[1 : len(rest)-1]
	} else if strings.HasPrefix(rest, "\"") && strings.HasSuffix(rest, "\"") {
		rest = rest[1 : len(rest)-1]
	}
	return field, rest
}

func parseRegexCondition(part string) (field, pattern string) {
	part = strings.TrimSpace(part)
	idx := strings.Index(part, "=~")
	if idx == -1 {
		return "", ""
	}
	field = strings.TrimSpace(part[:idx])
	rest := strings.TrimSpace(part[idx+2:])
	if strings.HasPrefix(rest, "`") && strings.HasSuffix(rest, "`") {
		rest = rest[1 : len(rest)-1]
	} else if strings.HasPrefix(rest, "\"") && strings.HasSuffix(rest, "\"") {
		rest = rest[1 : len(rest)-1]
	}
	return field, rest
}

func getFieldValue(field, title, body, header, status string) string {
	switch field {
	case "title":
		return title
	case "body":
		return body
	case "header":
		return header
	case "status":
		return status
	default:
		return ""
	}
}

type cachedResponse struct {
	title  string
	body   string
	header string
	status string
	raw    []byte
}

func scanIPPort(ctx context.Context, ip string, port int) {
	protocol := "http"
	if port == 443 || port == 8443 {
		protocol = "https"
	}

	pathRules := make(map[string][]Rule)
	for _, rule := range defaultRules {
		path := rule.Path
		if path == "" {
			path = "/"
		}
		pathRules[path] = append(pathRules[path], rule)
	}

	cache := make(map[string]*cachedResponse)

	for path := range pathRules {
		urlStr := fmt.Sprintf("%s://%s:%d%s", protocol, ip, port, path)
		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			continue
		}
		userAgent := *flagUserAgent
		if userAgent == "" {
			userAgent = getRandomUserAgent()
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "close")

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyStr := string(body)
		statusStr := fmt.Sprintf("%d", resp.StatusCode)

		title := ""
		if strings.Contains(bodyStr, "<title>") {
			parts := strings.SplitN(bodyStr, "<title>", 2)
			if len(parts) == 2 {
				parts2 := strings.SplitN(parts[1], "</title>", 2)
				if len(parts2) == 2 {
					title = strings.TrimSpace(parts2[0])
				}
			}
		}

		headerStr := ""
		for k, v := range resp.Header {
			headerStr += k + ": " + strings.Join(v, ", ") + "\n"
		}

		cache[path] = &cachedResponse{
			title:  title,
			body:   bodyStr,
			header: headerStr,
			status: statusStr,
			raw:    body,
		}
	}

	for _, rules := range pathRules {
		for _, rule := range rules {
			cached, ok := cache[rule.Path]
			if !ok {
				continue
			}
			if rule.MD5 != "" {
				hash := md5.Sum(cached.raw)
				hashHex := hex.EncodeToString(hash[:])
				if hashHex == rule.MD5 {
					reportResult(ip, port, rule.Vendor, rule.Product, fmt.Sprintf("MD5 match on %s", rule.Path))
					return
				}
				continue
			}
			if rule.Condition != "" {
				if evalCondition(rule.Condition, cached.title, cached.body, cached.header, cached.status) {
					reportResult(ip, port, rule.Vendor, rule.Product, fmt.Sprintf("condition match on %s", rule.Path))
					return
				}
			}
		}
	}
}

func reportResult(ip string, port int, vendor, product, details string) {
	res := Result{
		IP:      ip,
		Port:    port,
		Vendor:  vendor,
		Product: product,
		Details: details,
	}
	select {
	case resultsChan <- res:
	default:
	}
}

func worker(ctx context.Context, jobs <-chan string, ports []int) {
	defer wg.Done()
	for ip := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				default:
					scanIPPort(ctx, ip, port)
				}
			}
			atomic.AddInt64(&completed, 1)
		}
	}
}

func progressUpdater(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			progressMu.Lock()
			fmt.Fprintf(os.Stderr, "\r\033[K")
			progressMu.Unlock()
			return
		case <-ticker.C:
			done := atomic.LoadInt64(&completed)
			total := totalJobs
			if total == 0 {
				continue
			}
			pct := float64(done) / float64(total) * 100
			barWidth := 40
			filled := int(float64(barWidth) * float64(done) / float64(total))
			if filled > barWidth {
				filled = barWidth
			}
			barStr := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
			progressMu.Lock()
			fmt.Fprintf(os.Stderr, "\r\033[K[%s] %3.0f%% (%d/%d)", barStr, pct, done, total)
			progressMu.Unlock()
		}
	}
}

func resultWriter(ctx context.Context) {
	defer close(doneChan)
	var outMu sync.Mutex
	for {
		select {
		case <-ctx.Done():
			return
		case res, ok := <-resultsChan:
			if !ok {
				return
			}
			atomic.AddInt64(&foundCount, 1)

			line := fmt.Sprintf("%s:%d [%s] %s %s (%s)\n",
				res.IP, res.Port,
				color.GreenString("FOUND"),
				color.CyanString(res.Vendor),
				color.YellowString(res.Product),
				res.Details,
			)

			progressMu.Lock()
			fmt.Fprintf(os.Stderr, "\r\033[K")
			progressMu.Unlock()

			fmt.Print(line)

			if outFile != nil {
				outMu.Lock()
				plain := fmt.Sprintf("%s:%d [%s] %s %s (%s)\n",
					res.IP, res.Port, "FOUND", res.Vendor, res.Product, res.Details)
				if _, err := outFile.WriteString(plain); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
				}
				outMu.Unlock()
			}
		}
	}
}

func main() {
	flag.Parse()

	fmt.Printf("Routeglass - Coded By: K3ysTr0K3R\n")

	if *flagIP == "" && *flagFile == "" {
		fmt.Fprintf(os.Stderr, "Error: either -ip or -f must be provided\n")
		flag.Usage()
		os.Exit(1)
	}

	portStrs := strings.Split(*flagPorts, ",")
	var ports []int
	for _, ps := range portStrs {
		var p int
		_, err := fmt.Sscanf(ps, "%d", &p)
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintf(os.Stderr, "Invalid port: %s\n", ps)
			os.Exit(1)
		}
		ports = append(ports, p)
	}

	var targets []string
	if *flagIP != "" {
		ips, err := expandTarget(*flagIP)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error expanding -ip: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, ips...)
	}
	if *flagFile != "" {
		ips, err := loadTargetsFromFile(*flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, ips...)
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "No targets to scan\n")
		os.Exit(1)
	}
	seen := make(map[string]bool)
	unique := make([]string, 0, len(targets))
	for _, ip := range targets {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	targets = unique
	totalJobs = int64(len(targets))

	if *flagOutput != "" {
		var err error
		flagMode := os.O_CREATE | os.O_WRONLY
		if *flagAppend {
			flagMode |= os.O_APPEND
		} else {
			flagMode |= os.O_TRUNC
		}
		outFile, err = os.OpenFile(*flagOutput, flagMode, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	initHTTPClient()
	randSource = rand.New(rand.NewSource(time.Now().UnixNano()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupt received, shutting down gracefully...")
		cancel()
	}()

	go progressUpdater(ctx)

	jobs := make(chan string, 1000)
	numWorkers := *flagThreads
	if numWorkers < 1 {
		numWorkers = 1
	}
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker(ctx, jobs, ports)
	}

	go resultWriter(ctx)

	go func() {
		for _, ip := range targets {
			select {
			case <-ctx.Done():
				break
			case jobs <- ip:
			}
		}
		close(jobs)
	}()

	wg.Wait()
	close(resultsChan)
	<-doneChan

	progressMu.Lock()
	fmt.Fprintf(os.Stderr, "\r\033[K")
	progressMu.Unlock()

	found := atomic.LoadInt64(&foundCount)
	fmt.Printf("\nScan complete. %d targets scanned, %d device(s) found.\n", totalJobs, found)
}
