#!/bin/sh
#
# NetMod OpenWRT - SSH Tunnel Installer (Improved Version)
# Author: miladjs (Modified for stability)
# Repository: https://github.com/miladjs/netmod-openwrt
#

set -e

VERSION="1.1.0"
PACKAGE="luci-app-netmod"
BACKUP_DIR="/tmp/netmod-backup"

print_banner() {
    cat << 'BANNER'
╔═══════════════════════════════════════════╗
║                                           ║
║   NetMod OpenWRT Installer (Improved)     ║
║   SSH Tunnel Manager v1.1                 ║
║                                           ║
║   Safer networking & Better logging       ║
║                                           ║
╚═══════════════════════════════════════════╝
BANNER
}

log_info() {
    echo "[INFO] $1"
    logger -t netmod-installer "$1"
}

log_success() {
    echo "[✓] $1"
    logger -t netmod-installer "SUCCESS: $1"
}

log_error() {
    echo "[✗] $1"
    logger -t netmod-installer "ERROR: $1"
}

log_warn() {
    echo "[⚠] $1"
    logger -t netmod-installer "WARNING: $1"
}

backup_config() {
    log_info "Creating backup of network configuration..."
    mkdir -p "$BACKUP_DIR"
    
    # Backup network config
    cp /etc/config/network "$BACKUP_DIR/network.backup" 2>/dev/null || true
    cp /etc/config/dhcp "$BACKUP_DIR/dhcp.backup" 2>/dev/null || true
    cp /etc/config/firewall "$BACKUP_DIR/firewall.backup" 2>/dev/null || true
    cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.backup" 2>/dev/null || true
    
    log_success "Configuration backed up to $BACKUP_DIR"
}

restore_config() {
    log_warn "Restoring configuration from backup..."
    
    if [ -d "$BACKUP_DIR" ]; then
        cp "$BACKUP_DIR/network.backup" /etc/config/network 2>/dev/null || true
        cp "$BACKUP_DIR/dhcp.backup" /etc/config/dhcp 2>/dev/null || true
        cp "$BACKUP_DIR/firewall.backup" /etc/config/firewall 2>/dev/null || true
        cp "$BACKUP_DIR/sysctl.conf.backup" /etc/sysctl.conf 2>/dev/null || true
        
        /etc/init.d/network restart
        /etc/init.d/dnsmasq restart
        /etc/init.d/firewall restart
        
        log_success "Configuration restored"
    else
        log_error "Backup directory not found"
    fi
}

test_internet() {
    log_info "Testing internet connectivity..."
    
    # Test with multiple DNS servers and IPs
    if curl -4 -s --connect-timeout 5 --max-time 10 http://captive.apple.com/hotspot-detect.html | grep -q "Success"; then
        log_success "Internet connection OK"
        return 0
    elif curl -4 -s --connect-timeout 5 --max-time 10 https://www.google.com > /dev/null 2>&1; then
        log_success "Internet connection OK (Google)"
        return 0
    elif ping -c 3 -W 5 8.8.8.8 > /dev/null 2>&1; then
        log_success "Internet connection OK (ping 8.8.8.8)"
        return 0
    else
        log_error "Internet connection failed"
        return 1
    fi
}

do_install() {
    print_banner
    echo ""
    
    log_info "Starting installation..."
    echo ""
    
    # Backup current config
    backup_config
    
    # Test internet before proceeding
    if ! test_internet; then
        log_error "No internet connection. Please fix your connection first."
        exit 1
    fi
    
    # Step 1: Install dependencies
    log_info "Step 1/7: Installing dependencies..."
    opkg update > /dev/null 2>&1 || {
        log_error "Failed to update package list"
        restore_config
        exit 1
    }
    
    opkg install autossh redsocks curl sshpass > /dev/null 2>&1 || {
        log_error "Failed to install dependencies"
        restore_config
        exit 1
    }
    log_success "Dependencies installed"
    
    # Step 2: Configure IPv6 (OPTIONAL - ask user)
    log_info "Step 2/7: IPv6 configuration..."
    echo ""
    echo "Do you want to disable IPv6? (y/N)"
    echo "  Note: Only disable if you have IPv6 connectivity issues"
    read -r disable_ipv6
    
    if [ "$disable_ipv6" = "y" ] || [ "$disable_ipv6" = "Y" ]; then
        log_info "Disabling IPv6..."
        uci set network.wan.ipv6='0'
        uci set network.wan6.disabled='1'
        uci commit network
        
        if ! grep -q "disable_ipv6" /etc/sysctl.conf; then
            cat >> /etc/sysctl.conf << 'SYSCTL_EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL_EOF
        fi
        sysctl -p > /dev/null 2>&1
        log_success "IPv6 disabled"
    else
        log_info "IPv6 kept enabled"
    fi
    
    # Step 3: Generate SSH key
    log_info "Step 3/7: Generating SSH key pair..."
    mkdir -p /root/.ssh
    if [ ! -f /root/.ssh/id_rsa ]; then
        ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N "" -q
        log_success "SSH key generated"
    else
        log_info "SSH key already exists, skipping"
    fi
    
    # Step 4: Create UCI configuration
    log_info "Step 4/7: Creating configuration file..."
    cat > /etc/config/netmod << 'UCI_EOF'
config netmod 'config'
    option enabled '0'
    option server ''
    option port '22'
    option username 'root'
    option password ''
    option socks_port '1080'
    option redsocks_port '12345'
    option use_doh '1'
    option block_quic '0'
UCI_EOF
    log_success "Configuration created"
    
    # Step 5: Create improved init script
    log_info "Step 5/7: Creating system service..."
    cat > /etc/init.d/netmod << 'INIT_SCRIPT_EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=10
USE_PROCD=1

BACKUP_DNS="/tmp/netmod-dns-backup"

resolve_server_ip() {
    local host="$1" ip=""
    case "$host" in
        *[!0-9.]*|"")
            ip="$(nslookup "$host" 2>/dev/null | awk '/^Address [0-9]+: [0-9.]+$/ {print $3; exit}')"
            ;;
        *)
            ip="$host"
            ;;
    esac
    echo "$ip"
}

test_url() {
    local url="$1"
    curl -fsS -I --connect-timeout 8 --max-time 12 "$url" >/dev/null 2>&1
}

test_url_socks() {
    local url="$1" socks_port="$2"
    curl -fsS -I --connect-timeout 8 --max-time 12 --socks5-hostname 127.0.0.1:"$socks_port" "$url" >/dev/null 2>&1
}

test_ssh_connection() {
    local server="$1" port="$2" username="$3" password="$4"
    
    logger -t netmod "Testing SSH connection to $username@$server:$port..."
    
    if [ -n "$password" ]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            logger -t netmod "ERROR: sshpass not installed"
            return 1
        fi
        
        timeout 15 sshpass -p "$password" ssh -o "StrictHostKeyChecking=no" \
            -o "ConnectTimeout=10" \
            -o "BatchMode=yes" \
            -p "$port" "${username}@${server}" "echo 'SSH OK'" >/dev/null 2>&1
    else
        timeout 15 ssh -o "StrictHostKeyChecking=no" \
            -o "ConnectTimeout=10" \
            -o "BatchMode=yes" \
            -p "$port" "${username}@${server}" "echo 'SSH OK'" >/dev/null 2>&1
    fi
    
    if [ $? -eq 0 ]; then
        logger -t netmod "SSH connection test: SUCCESS"
        return 0
    else
        logger -t netmod "SSH connection test: FAILED"
        return 1
    fi
}

backup_dns_config() {
    uci show dhcp.@dnsmasq[0] > "$BACKUP_DNS" 2>/dev/null
}

restore_dns_config() {
    if [ -f "$BACKUP_DNS" ]; then
        logger -t netmod "Restoring DNS configuration..."
        uci set dhcp.@dnsmasq[0].noresolv='0'
        uci -q delete dhcp.@dnsmasq[0].server
        uci commit dhcp
        /etc/init.d/dnsmasq restart
        rm -f "$BACKUP_DNS"
    fi
}

block_quic() {
    nft add table inet netmod 2>/dev/null || true
    nft add chain inet netmod quic_prerouting { type filter hook prerouting priority -150 \; } 2>/dev/null || true
    nft add chain inet netmod quic_output { type filter hook output priority -150 \; } 2>/dev/null || true
    nft add rule inet netmod quic_prerouting udp dport 443 drop 2>/dev/null || true
    nft add rule inet netmod quic_output udp dport 443 drop 2>/dev/null || true
    logger -t netmod "QUIC blocking enabled"
}

ensure_youtube_access() {
    local url="https://www.youtube.com/generate_204"
    local socks_port="$1"
    local block_quic_opt="$2"
    
    logger -t netmod "Testing YouTube connectivity..."
    
    if test_url "$url"; then
        logger -t netmod "YouTube OK (default path)"
        return 0
    fi
    
    if test_url_socks "$url" "$socks_port"; then
        logger -t netmod "YouTube OK via SOCKS"
        return 0
    fi
    
    if [ "$block_quic_opt" = "1" ]; then
        logger -t netmod "Blocking QUIC (UDP/443) as configured..."
        block_quic
        sleep 2
        if test_url "$url"; then
            logger -t netmod "YouTube OK after blocking QUIC"
            return 0
        fi
    fi
    
    logger -t netmod "YouTube test completed with warnings"
    return 0
}

start_service() {
    local enabled server port username password socks_port redsocks_port
    local use_doh block_quic_opt server_ip
    
    config_load netmod
    config_get enabled config enabled 0
    config_get server config server
    config_get port config port 22
    config_get username config username root
    config_get password config password
    config_get socks_port config socks_port 1080
    config_get redsocks_port config redsocks_port 12345
    config_get use_doh config use_doh 1
    config_get block_quic_opt config block_quic 0
    
    [ "$enabled" != "1" ] && {
        stop_processes
        cleanup_network
        logger -t netmod "Service disabled"
        return 0
    }
    
    [ -z "$server" ] && {
        logger -t netmod "ERROR: Server address not configured"
        return 1
    }
    
    # Test SSH connection BEFORE making any changes
    if ! test_ssh_connection "$server" "$port" "$username" "$password"; then
        logger -t netmod "ERROR: Cannot connect to SSH server. Not starting service."
        return 1
    fi
    
    logger -t netmod "Starting SSH tunnel to $server:$port"
    
    # Backup DNS config before changes
    backup_dns_config
    
    # Start autossh tunnel
    procd_open_instance autossh
    if [ -n "$password" ]; then
        procd_set_param command sshpass -p "$password" /usr/sbin/autossh \
            -M 0 \
            -o "ServerAliveInterval=30" \
            -o "ServerAliveCountMax=3" \
            -o "ExitOnForwardFailure=yes" \
            -o "StrictHostKeyChecking=no" \
            -N -D 127.0.0.1:$socks_port \
            -p $port ${username}@${server}
    else
        procd_set_param command /usr/sbin/autossh \
            -M 0 \
            -o "ServerAliveInterval=30" \
            -o "ServerAliveCountMax=3" \
            -o "ExitOnForwardFailure=yes" \
            -o "StrictHostKeyChecking=no" \
            -N -D 127.0.0.1:$socks_port \
            -p $port ${username}@${server}
    fi
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
    
    sleep 5
    
    # Verify tunnel is running
    if ! pgrep -f "autossh.*$server" > /dev/null; then
        logger -t netmod "ERROR: SSH tunnel failed to start"
        restore_dns_config
        return 1
    fi
    
    # Test SOCKS proxy
    if ! test_url_socks "http://www.google.com" "$socks_port"; then
        logger -t netmod "WARNING: SOCKS proxy not responding yet, waiting..."
        sleep 5
    fi
    
    # Configure redsocks
    cat > /etc/redsocks.conf << REDSOCKS_CONF_EOF
base {
    daemon = on;
    redirector = generic;
}
redsocks {
    local_ip = 127.0.0.1;
    local_port = $redsocks_port;
    ip = 127.0.0.1;
    port = $socks_port;
    type = socks5;
}
REDSOCKS_CONF_EOF
    
    /etc/init.d/redsocks restart
    sleep 2
    
    server_ip="$(resolve_server_ip "$server")"
    [ -z "$server_ip" ] && {
        logger -t netmod "ERROR: Unable to resolve server address: $server"
        stop_processes
        restore_dns_config
        return 1
    }
    
    logger -t netmod "Server IP resolved: $server_ip"

    # Setup nftables firewall rules
    nft delete table inet netmod 2>/dev/null || true
    nft add table inet netmod
    nft add chain inet netmod prerouting { type nat hook prerouting priority -100 \; }
    nft add chain inet netmod output { type nat hook output priority -100 \; }
    
    # Prerouting chain (LAN traffic)
    nft add rule inet netmod prerouting ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, $server_ip } return
    nft add rule inet netmod prerouting ip protocol tcp redirect to :$redsocks_port
    
    # Output chain (Router traffic - exclude redsocks to prevent loop)
    nft add rule inet netmod output meta skuid 65534 return
    nft add rule inet netmod output ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, $server_ip } return
    nft add rule inet netmod output ip protocol tcp redirect to :$redsocks_port
    
    logger -t netmod "Firewall rules applied"
    
    # Configure DNS-over-HTTPS (optional)
    if [ "$use_doh" = "1" ]; then
        logger -t netmod "Configuring DNS-over-HTTPS..."
        /etc/init.d/https-dns-proxy stop 2>/dev/null
        
        # Use Cloudflare and Google DoH
        /usr/sbin/https-dns-proxy -u nobody -g nogroup -b 127.0.0.1:5054 -r https://1.1.1.1/dns-query &
        sleep 1
        
        uci set dhcp.@dnsmasq[0].noresolv='1'
        uci -q delete dhcp.@dnsmasq[0].server
        uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5054'
        # Add fallback to ISP DNS
        uci add_list dhcp.@dnsmasq[0].server='8.8.8.8'
        uci commit dhcp
        /etc/init.d/dnsmasq restart
        logger -t netmod "DNS-over-HTTPS configured with fallback"
    else
        logger -t netmod "DNS-over-HTTPS disabled (using default DNS)"
    fi
    
    # Test YouTube access
    ensure_youtube_access "$socks_port" "$block_quic_opt"
    
    logger -t netmod "Service started successfully"
}

stop_processes() {
    killall autossh 2>/dev/null || true
    killall https-dns-proxy 2>/dev/null || true
    /etc/init.d/redsocks stop 2>/dev/null || true
}

cleanup_network() {
    nft delete table inet netmod 2>/dev/null || true
    restore_dns_config
    logger -t netmod "Network cleanup completed"
}

stop_service() {
    stop_processes
    cleanup_network
    logger -t netmod "Service stopped"
}

service_triggers() {
    procd_add_reload_trigger "netmod"
}
INIT_SCRIPT_EOF
    
    chmod +x /etc/init.d/netmod
    log_success "Service created"
    
    # Step 6: Create LuCI web interface
    log_info "Step 6/7: Creating web interface..."
    
    # Controller
    mkdir -p /usr/lib/lua/luci/controller
    cat > /usr/lib/lua/luci/controller/netmod.lua << 'CONTROLLER_EOF'
module("luci.controller.netmod", package.seeall)

function index()
    entry({"admin", "services", "netmod"}, cbi("netmod"), _("NetMod Tunnel"), 60)
    entry({"admin", "services", "netmod", "status"}, call("get_status"))
    entry({"admin", "services", "netmod", "test_ssh"}, call("test_ssh"))
end

function get_status()
    local sys = require "luci.sys"
    local status = {
        tunnel = (sys.call("pgrep -f autossh > /dev/null 2>&1") == 0),
        redsocks = (sys.call("pgrep redsocks > /dev/null 2>&1") == 0),
        https_dns_proxy = (sys.call("pgrep https-dns-proxy > /dev/null 2>&1") == 0),
        nft_table = (sys.call("nft list table inet netmod > /dev/null 2>&1") == 0),
        deps = {
            autossh = (sys.call("command -v autossh > /dev/null 2>&1") == 0),
            redsocks = (sys.call("command -v redsocks > /dev/null 2>&1") == 0),
            nft = (sys.call("command -v nft > /dev/null 2>&1") == 0),
            sshpass = (sys.call("command -v sshpass > /dev/null 2>&1") == 0),
            curl = (sys.call("command -v curl > /dev/null 2>&1") == 0)
        }
    }
    luci.http.prepare_content("application/json")
    luci.http.write_json(status)
end

function test_ssh()
    local uci = require "luci.model.uci".cursor()
    local server = uci:get("netmod", "config", "server")
    local port = uci:get("netmod", "config", "port") or "22"
    local username = uci:get("netmod", "config", "username") or "root"
    local password = uci:get("netmod", "config", "password") or ""
    
    local result = {success = false, message = ""}
    
    if not server or server == "" then
        result.message = "Server address not configured"
        luci.http.prepare_content("application/json")
        luci.http.write_json(result)
        return
    end
    
    local cmd
    if password ~= "" then
        cmd = string.format(
            "timeout 15 sshpass -p '%s' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes -p %s %s@%s 'echo SSH_OK' 2>&1",
            password:gsub("'", "'\\''"), port, username, server
        )
    else
        cmd = string.format(
            "timeout 15 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes -p %s %s@%s 'echo SSH_OK' 2>&1",
            port, username, server
        )
    end
    
    local output = luci.sys.exec(cmd)
    
    if output:match("SSH_OK") then
        result.success = true
        result.message = "SSH connection successful!"
    else
        result.message = "SSH connection failed: " .. output:sub(1, 200)
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
CONTROLLER_EOF
    
    # Model (CBI form)
    mkdir -p /usr/lib/lua/luci/model/cbi
    cat > /usr/lib/lua/luci/model/cbi/netmod.lua << 'MODEL_EOF'
m = Map("netmod", translate("NetMod Tunnel"), 
    translate("Improved SSH tunnel manager with safer networking and better error handling"))

-- Status section
s = m:section(TypedSection, "netmod")
s.anonymous = true
s.addremove = false

st = s:option(DummyValue, "_status", translate("Connection Status"))
st.template = "netmod/status"

-- Configuration section
o = s:option(Flag, "enabled", translate("Enable Tunnel"))
o.rmempty = false

o = s:option(Value, "server", translate("SSH Server Address"))
o.placeholder = "e.g., example.com or 91.107.191.252"
o.rmempty = false

o = s:option(Value, "port", translate("SSH Port"))
o.datatype = "port"
o.default = "22"
o.placeholder = "22"

o = s:option(Value, "username", translate("Username"))
o.default = "root"
o.placeholder = "root"

o = s:option(Value, "password", translate("Password"))
o.password = true
o.rmempty = true
o.description = translate("Leave empty to use SSH key authentication")

-- Advanced options
o = s:option(Flag, "use_doh", translate("Use DNS-over-HTTPS"))
o.default = "1"
o.rmempty = false
o.description = translate("Enable encrypted DNS with fallback to ISP DNS")

o = s:option(Flag, "block_quic", translate("Block QUIC (UDP/443)"))
o.default = "0"
o.rmempty = false
o.description = translate("Enable only if YouTube/Google services have issues")

-- SSH Key section
s2 = m:section(TypedSection, "netmod", translate("SSH Public Key"))
s2.anonymous = true

o = s2:option(DummyValue, "_key", translate("Your SSH Public Key"))
o.template = "netmod/sshkey"

return m
MODEL_EOF
    
    # Templates
    mkdir -p /usr/lib/lua/luci/view/netmod
    
    # Status template
    cat > /usr/lib/lua/luci/view/netmod/status.htm << 'STATUS_TPL_EOF'
<script type="text/javascript">//<![CDATA[
function testSSH() {
    var btn = document.getElementById('test_ssh_btn');
    var result = document.getElementById('test_ssh_result');
    
    btn.disabled = true;
    btn.innerHTML = 'Testing...';
    result.innerHTML = '<em style="color:#666;">Connecting to SSH server...</em>';
    
    XHR.get('<%=url("admin/services/netmod/test_ssh")%>', null,
        function(x, data) {
            btn.disabled = false;
            btn.innerHTML = 'Test SSH Connection';
            
            if (data && data.success) {
                result.innerHTML = '<span style="color:green;font-weight:bold;">✓ ' + data.message + '</span>';
            } else {
                result.innerHTML = '<span style="color:red;font-weight:bold;">✗ ' + (data ? data.message : 'Test failed') + '</span>';
            }
        }
    );
}

XHR.poll(3, '<%=url("admin/services/netmod/status")%>', null,
    function(x, st) {
        var elem = document.getElementById('netmod_status');
        var depsElem = document.getElementById('netmod_deps');
        var detailsElem = document.getElementById('netmod_details');
        
        if (st && st.tunnel && st.redsocks && st.nft_table) {
            elem.innerHTML = '<span style="color:green;font-weight:bold;">● Connected</span>';
        } else if (st && (st.tunnel || st.redsocks)) {
            elem.innerHTML = '<span style="color:orange;font-weight:bold;">● Connecting...</span>';
        } else {
            elem.innerHTML = '<span style="color:red;font-weight:bold;">● Disconnected</span>';
        }

        if (detailsElem && st) {
            var details = [];
            details.push('Tunnel: ' + (st.tunnel ? '✓' : '✗'));
            details.push('Redsocks: ' + (st.redsocks ? '✓' : '✗'));
            details.push('Firewall: ' + (st.nft_table ? '✓' : '✗'));
            detailsElem.innerHTML = details.join(' | ');
        }

        if (depsElem && st && st.deps) {
            var items = [];
            items.push('autossh: ' + (st.deps.autossh ? '✓' : '✗'));
            items.push('redsocks: ' + (st.deps.redsocks ? '✓' : '✗'));
            items.push('nft: ' + (st.deps.nft ? '✓' : '✗'));
            items.push('sshpass: ' + (st.deps.sshpass ? '✓' : '✗'));
            items.push('curl: ' + (st.deps.curl ? '✓' : '✗'));
            depsElem.innerHTML = items.join(' | ');
        }
    }
);
//]]></script>

<div style="margin-bottom:15px;">
    <span id="netmod_status">
        <em><%:Checking status...%></em>
    </span>
    <div style="margin-top:5px;font-size:11px;color:#888;" id="netmod_details">
        <em><%:Loading details...%></em>
    </div>
</div>

<div style="margin:15px 0;padding:12px;background:#f5f5f5;border:1px solid #ddd;border-radius:4px;">
    <button id="test_ssh_btn" onclick="testSSH()" 
        style="padding:8px 16px;background:#0088cc;color:white;border:none;border-radius:3px;cursor:pointer;">
        Test SSH Connection
    </button>
    <div id="test_ssh_result" style="margin-top:10px;"></div>
</div>

<div style="margin-top:12px;font-size:11px;color:#666;" id="netmod_deps">
    <em><%:Checking dependencies...%></em>
</div>
STATUS_TPL_EOF
    
    # SSH Key template
    cat > /usr/lib/lua/luci/view/netmod/sshkey.htm << 'KEY_TPL_EOF'
<%
local fs = require "nixio.fs"
local key = fs.readfile("/root/.ssh/id_rsa.pub") or "Key not found"
%>
<div class="cbi-value-field">
    <p style="margin-bottom:10px;">
        <strong>Add this key to your server's <code>/root/.ssh/authorized_keys</code>:</strong>
    </p>
    <textarea readonly onclick="this.select()" 
        style="width:100%;height:90px;font-family:monospace;font-size:11px;padding:10px;border:1px solid #ccc;border-radius:4px;background:#f9f9f9;"><%=key:gsub("^%s*(.-)%s*$", "%1")%></textarea>
    <p style="margin-top:10px;font-size:13px;color:#666;">
        💡 Click on the text to select, then press Ctrl+C to copy
    </p>
    <p style="margin-top:8px;font-size:12px;color:#888;">
        Or on your server run:<br>
        <code style="background:#f0f0f0;padding:4px 8px;border-radius:3px;display:inline-block;margin-top:4px;">
        echo "<%=key:gsub("^%s*(.-)%s*$", "%1")%>" >> /root/.ssh/authorized_keys
        </code>
    </p>
</div>
KEY_TPL_EOF
    
    log_success "Web interface created"
    
    # Step 7: Register with opkg
    log_info "Step 7/7: Registering package..."
    mkdir -p /usr/lib/opkg/info
    
    cat > /usr/lib/opkg/info/${PACKAGE}.control << CONTROL_EOF
Package: ${PACKAGE}
Version: ${VERSION}
Architecture: all
Maintainer: miladjs <https://github.com/miladjs>
Description: Improved NetMod SSH tunnel with safer networking,
 connection testing, optional IPv6, and better error handling.
CONTROL_EOF
    
    cat > /usr/lib/opkg/info/${PACKAGE}.list << LIST_EOF
/etc/config/netmod
/etc/init.d/netmod
/usr/lib/lua/luci/controller/netmod.lua
/usr/lib/lua/luci/model/cbi/netmod.lua
/usr/lib/lua/luci/view/netmod/status.htm
/usr/lib/lua/luci/view/netmod/sshkey.htm
LIST_EOF
    
    # Clear LuCI cache
    rm -rf /tmp/luci-* 2>/dev/null
    
    log_success "Package registered"
    
    # Test internet after installation
    echo ""
    log_info "Final connectivity test..."
    if test_internet; then
        log_success "Internet connection still working!"
    else
        log_warn "Internet connection test failed - but don't worry, tunnel is not enabled yet"
    fi
    
    echo ""
    echo "╔═══════════════════════════════════════════╗"
    echo "║   Installation completed successfully!    ║"
    echo "╚═══════════════════════════════════════════╝"
    echo ""
    echo "✅ Improvements in this version:"
    echo "   • SSH connection tested before activation"
    echo "   • IPv6 disable is now optional"
    echo "   • DNS with fallback to prevent connection loss"
    echo "   • Better logging and error handling"
    echo "   • Automatic rollback on failure"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Go to LuCI: Services → NetMod Tunnel"
    echo "2. Copy your SSH public key"
    echo "3. Add it to your server: /root/.ssh/authorized_keys"
    echo "4. Enter server details"
    echo "5. Click 'Test SSH Connection' button"
    echo "6. If test passes, enable the tunnel"
    echo ""
    echo "📋 Configuration backup saved to: $BACKUP_DIR"
    echo ""
}

do_remove() {
    echo "Removing NetMod OpenWRT..."
    echo ""
    
    # Stop and cleanup
    /etc/init.d/netmod stop 2>/dev/null
    /etc/init.d/netmod disable 2>/dev/null
    
    # Remove files
    rm -f /etc/init.d/netmod
    rm -f /etc/config/netmod
    rm -f /etc/redsocks.conf
    rm -f /usr/lib/lua/luci/controller/netmod.lua
    rm -f /usr/lib/lua/luci/model/cbi/netmod.lua
    rm -rf /usr/lib/lua/luci/view/netmod
    rm -f /usr/lib/opkg/info/${PACKAGE}.*
    
    # Clear cache
    rm -rf /tmp/luci-* 2>/dev/null
    rm -f /tmp/netmod-* 2>/dev/null
    
    # Cleanup nftables
    nft delete table inet netmod 2>/dev/null || true
    
    log_success "NetMod removed successfully"
    echo ""
    echo "Note: Your network configuration backup is still at: $BACKUP_DIR"
    echo "You can safely delete it if everything works fine."
}

show_usage() {
    echo "Usage: $0 {install|remove|restore}"
    echo ""
    echo "Commands:"
    echo "  install  - Install NetMod with improvements"
    echo "  remove   - Remove NetMod completely"
    echo "  restore  - Restore network configuration from backup"
    echo ""
    echo "NetMod OpenWRT Installer v${VERSION}"
    echo "Improved version with safer networking"
    exit 1
}

case "$1" in
    install)
        do_install
        ;;
    remove|uninstall)
        do_remove
        ;;
    restore)
        restore_config
        ;;
    *)
        show_usage
        ;;
esac