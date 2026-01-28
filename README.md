cat > README.md << 'README_EOF'
# NetMod OpenWRT

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenWRT](https://img.shields.io/badge/OpenWRT-24.10+-blue.svg)](https://openwrt.org/)

SSH tunnel manager for OpenWRT routers to bypass internet filtering. Provides a web-based interface similar to NetMod for Windows.

## Features

✅ **Easy Installation** - One-line installer  
✅ **Web Interface** - LuCI integration for easy management  
✅ **Auto-reconnect** - Uses `autossh` for reliable connections  
✅ **Transparent Proxy** - Automatic traffic redirection  
✅ **DNS-over-HTTPS** - Encrypted DNS queries  
✅ **IPv6 Disabled** - Prevents IPv6 leaks  

## Quick Start

### Installation

SSH into your OpenWRT router and run:
```bash
wget -O /install.sh https://raw.githubusercontent.com/miladjs/netmod-openwrt/main/install.sh
sh /install.sh install
```

Or using curl:
```bash
curl -fsSL https://raw.githubusercontent.com/miladjs/netmod-openwrt/main/install.sh -o /install.sh
sh /install.sh install
```

### Configuration

1. **Access Web Interface**
   - Navigate to `Services → NetMod Tunnel` in LuCI

2. **Copy SSH Key**
   - The interface displays your SSH public key
   - Copy this key

3. **Add Key to Server**
   - SSH into your remote server
   - Run:
```bash
     mkdir -p /root/.ssh
     nano /root/.ssh/authorized_keys
```
   - Paste the key (new line)
   - Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`)
   - Set permissions:
```bash
     chmod 600 /root/.ssh/authorized_keys
```

4. **Enable Tunnel**
   - Enter your server address (e.g., `91.107.191.252`)
   - Enter SSH port (default: `22`)
   - Enter username (default: `root`)
   - Check "Enable Tunnel"
   - Click "Save & Apply"

### Testing

After enabling the tunnel, test connectivity:
```bash
# Test SOCKS proxy directly
curl --socks5 127.0.0.1:1080 -I https://google.com

# Test transparent proxy
curl -I https://youtube.com
```

## How It Works
```
┌─────────────┐         ┌──────────────┐         ┌────────────┐
│   Client    │────────▶│   OpenWRT    │────────▶│   Remote   │
│  (LAN/WiFi) │         │    Router    │   SSH   │   Server   │
└─────────────┘         └──────────────┘         └────────────┘
                              │
                              ├─ autossh (SSH tunnel)
                              ├─ redsocks (SOCKS5 → transparent)
                              ├─ nftables (traffic redirect)
                              └─ https-dns-proxy (DNS-over-HTTPS)
```

1. **SSH Tunnel**: Creates SOCKS5 proxy on port 1080
2. **Redsocks**: Converts SOCKS5 to transparent proxy
3. **nftables**: Redirects TCP traffic to redsocks
4. **DNS-over-HTTPS**: Encrypts DNS queries to prevent poisoning

## Requirements

- OpenWRT 24.10+ (with nftables support)
- SSH server with key-based authentication
- Minimum 4MB free storage

## Management

### Start/Stop Service
```bash
# Start
/etc/init.d/netmod start

# Stop
/etc/init.d/netmod stop

# Restart
/etc/init.d/netmod restart

# Status
/etc/init.d/netmod status
```

### Enable/Disable Auto-start
```bash
# Enable auto-start on boot
/etc/init.d/netmod enable

# Disable auto-start
/etc/init.d/netmod disable
```

### View Logs
```bash
logread | grep netmod
```

### Manual Configuration

Edit `/etc/config/netmod`:
```bash
config netmod 'config'
    option enabled '1'
    option server '91.107.191.252'
    option port '22'
    option username 'root'
    option socks_port '1080'
    option redsocks_port '12345'
```

Apply changes:
```bash
uci commit netmod
/etc/init.d/netmod restart
```

## Uninstallation
```bash
sh /install.sh remove
```

Or using opkg:
```bash
opkg remove luci-app-netmod
```

## Troubleshooting

### Connection fails

1. **Check SSH key authentication**:
```bash
   ssh -o StrictHostKeyChecking=no root@YOUR_SERVER "echo OK"
```
   Should print "OK" without password prompt.

2. **Check tunnel status**:
```bash
   ps | grep autossh
   netstat -ln | grep 1080
```

3. **Check logs**:
```bash
   logread | grep -E "netmod|autossh|redsocks"
```

### DNS not working
```bash
# Check DNS-over-HTTPS
ps | grep https-dns-proxy
netstat -ln | grep -E "5053|5054"

# Test DNS
nslookup google.com
```

### Firewall rules missing
```bash
# View current rules
nft list table inet netmod

# Restart service to recreate rules
/etc/init.d/netmod restart
```

## Advanced Usage

### Custom SOCKS Port
```bash
uci set netmod.config.socks_port='9050'
uci commit netmod
/etc/init.d/netmod restart
```

### Exclude Specific IPs

Edit `/etc/init.d/netmod` and add IPs to the return rule:
```bash
nft add rule inet netmod prerouting ip daddr { ..., YOUR_IP } return
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**miladjs**  
GitHub: [@miladjs](https://github.com/miladjs)

## Acknowledgments

- Inspired by NetMod for Windows
- Built for OpenWRT community
- Uses autossh, redsocks, and https-dns-proxy

---

⭐ If you find this project useful, please give it a star!
README_EOF
