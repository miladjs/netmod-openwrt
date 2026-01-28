cat > install.sh << 'INSTALL_EOF'
#!/bin/sh
#
# NetMod OpenWRT - SSH Tunnel Installer
# Author: miladjs
# Repository: https://github.com/miladjs/netmod-openwrt
# Description: NetMod is a free, advanced VPN client and set of network tool, offering VPN protocols including SSH, HTTP(S), Socks, VMess, VLess, Trojan, Shadowsocks
#

set -e

VERSION="1.0.0"
PACKAGE="luci-app-netmod"

print_banner() {
    cat << 'BANNER'
╔═══════════════════════════════════════════╗
║                                           ║
║       NetMod OpenWRT Installer            ║
║       SSH Tunnel Manager v1.0             ║
║                                           ║
║       Author: miladjs                     ║
║       github.com/miladjs/netmod-openwrt   ║
║                                           ║
╚═══════════════════════════════════════════╝
BANNER
}

log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[✓] $1"
}

log_error() {
    echo "[✗] $1"
}

do_install() {
    print_banner
    echo ""
    
    log_info "Starting installation..."
    echo ""
    
    # Step 1: Install dependencies
    log_info "Step 1/7: Installing dependencies..."
    opkg update > /dev/null 2>&1
    opkg install autossh redsocks https-dns-proxy luci-compat curl sshpass > /dev/null 2>&1
    log_success "Dependencies installed"
    
    # Step 2: Disable IPv6
    log_info "Step 2/7: Configuring network (disabling IPv6)..."
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
UCI_EOF
    log_success "Configuration created"
    
    # Step 5: Create init script
    log_info "Step 5/7: Creating system service..."
    cat > /etc/init.d/netmod << 'INIT_SCRIPT_EOF'
#!/bin/sh /etc/rc.common

START=99
STOP=10
USE_PROCD=1

start_service() {
    local enabled server port username password socks_port redsocks_port
    
    config_load netmod
    config_get enabled config enabled 0
    config_get server config server
    config_get port config port 22
    config_get username config username root
    config_get password config password
    config_get socks_port config socks_port 1080
    config_get redsocks_port config redsocks_port 12345
    
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
    
    logger -t netmod "Starting SSH tunnel to $server:$port"
    
    if [ -n "$password" ]; then
        local sshpass_path
        sshpass_path="$(command -v sshpass 2>/dev/null)"
        [ -z "$sshpass_path" ] && {
            logger -t netmod "ERROR: sshpass not installed"
            return 1
        }
    fi
    
    # Start autossh tunnel
    procd_open_instance autossh
    if [ -n "$password" ]; then
        procd_set_param command "$sshpass_path" -p "$password" /usr/sbin/autossh \
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
    
    sleep 3
    
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
    
    # Setup nftables firewall rules
    nft delete table inet netmod 2>/dev/null
    nft add table inet netmod
    nft add chain inet netmod prerouting { type nat hook prerouting priority -100 \; }
    nft add chain inet netmod output { type nat hook output priority -100 \; }
    
    # Prerouting chain (LAN traffic)
    nft add rule inet netmod prerouting ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, $server } return
    nft add rule inet netmod prerouting ip protocol tcp redirect to :$redsocks_port
    
    # Output chain (Router traffic - exclude redsocks user to prevent loop)
    nft add rule inet netmod output meta skuid 65534 return
    nft add rule inet netmod output ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4, $server } return
    nft add rule inet netmod output ip protocol tcp redirect to :$redsocks_port
    
    # Configure DNS-over-HTTPS
    /etc/init.d/https-dns-proxy start
    uci set dhcp.@dnsmasq[0].noresolv='1'
    uci -q delete dhcp.@dnsmasq[0].server
    uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5053'
    uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5054'
    uci commit dhcp
    /etc/init.d/dnsmasq restart
    
    logger -t netmod "Service started successfully"
}

stop_processes() {
    killall autossh 2>/dev/null
    /etc/init.d/redsocks stop
}

cleanup_network() {
    nft delete table inet netmod 2>/dev/null
    
    uci set dhcp.@dnsmasq[0].noresolv='0'
    uci -q delete dhcp.@dnsmasq[0].server
    uci commit dhcp
    /etc/init.d/dnsmasq restart
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
end

function get_status()
    local sys = require "luci.sys"
    local status = {
        tunnel = (sys.call("pgrep -f autossh > /dev/null 2>&1") == 0),
        redsocks = (sys.call("pgrep redsocks > /dev/null 2>&1") == 0),
        https_dns_proxy = (sys.call("pgrep https-dns-proxy > /dev/null 2>&1") == 0),
        deps = {
            autossh = (sys.call("command -v autossh > /dev/null 2>&1") == 0),
            redsocks = (sys.call("command -v redsocks > /dev/null 2>&1") == 0),
            https_dns_proxy = (sys.call("command -v https-dns-proxy > /dev/null 2>&1") == 0),
            nft = (sys.call("command -v nft > /dev/null 2>&1") == 0),
            sshpass = (sys.call("command -v sshpass > /dev/null 2>&1") == 0)
        }
    }
    luci.http.prepare_content("application/json")
    luci.http.write_json(status)
end
CONTROLLER_EOF
    
    # Model (CBI form)
    mkdir -p /usr/lib/lua/luci/model/cbi
    cat > /usr/lib/lua/luci/model/cbi/netmod.lua << 'MODEL_EOF'
m = Map("netmod", translate("NetMod"), 
    translate("NetMod is a free, advanced VPN client and set of network tool, offering VPN protocols including SSH, HTTP(S), Socks, VMess, VLess, Trojan, Shadowsocks"))

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
o.placeholder = "e.g., 91.107.191.252"
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
XHR.poll(3, '<%=url("admin/services/netmod/status")%>', null,
    function(x, st) {
        var elem = document.getElementById('netmod_status');
        var depsElem = document.getElementById('netmod_deps');
        if (st && st.tunnel && st.redsocks) {
            elem.innerHTML = '<span style="color:green;font-weight:bold">● Connected</span>';
        } else if (st && (st.tunnel || st.redsocks)) {
            elem.innerHTML = '<span style="color:orange;font-weight:bold">● Connecting...</span>';
        } else {
            elem.innerHTML = '<span style="color:red;font-weight:bold">● Disconnected</span>';
        }

        if (depsElem && st && st.deps) {
            var items = [];
            items.push('autossh: ' + (st.deps.autossh ? 'OK' : 'Missing'));
            items.push('redsocks: ' + (st.deps.redsocks ? 'OK' : 'Missing'));
            items.push('https-dns-proxy: ' + (st.deps.https_dns_proxy ? 'OK' : 'Missing'));
            items.push('nft: ' + (st.deps.nft ? 'OK' : 'Missing'));
            items.push('sshpass: ' + (st.deps.sshpass ? 'OK' : 'Missing'));
            depsElem.innerHTML = items.join(' | ');
        }
    }
);
//]]></script>
<span id="netmod_status">
    <em><%:Checking status...%></em>
</span>
<div style="margin-top:8px;font-size:12px;color:#666;" id="netmod_deps">
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
Description: NetMod is a free, advanced VPN client and set of network tool,
 offering VPN protocols including SSH, HTTP(S), Socks, VMess, VLess, Trojan,
 Shadowsocks.
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
    
    echo ""
    echo "╔═══════════════════════════════════════════╗"
    echo "║   Installation completed successfully!    ║"
    echo "╚═══════════════════════════════════════════╝"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Go to LuCI web interface: Services → NetMod Tunnel"
    echo "2. Copy your SSH public key"
    echo "3. Add it to your server's /root/.ssh/authorized_keys"
    echo "4. Enter server details and enable the tunnel"
    echo ""
    echo "Test connection:"
    echo "  curl -I https://youtube.com"
    echo ""
}

do_remove() {
    echo "Removing NetMod OpenWRT..."
    echo ""
    
    /etc/init.d/netmod stop 2>/dev/null
    /etc/init.d/netmod disable 2>/dev/null
    
    rm -f /etc/init.d/netmod
    rm -f /etc/config/netmod
    rm -f /usr/lib/lua/luci/controller/netmod.lua
    rm -f /usr/lib/lua/luci/model/cbi/netmod.lua
    rm -rf /usr/lib/lua/luci/view/netmod
    rm -f /usr/lib/opkg/info/${PACKAGE}.*
    
    rm -rf /tmp/luci-* 2>/dev/null
    
    log_success "NetMod removed successfully"
}

show_usage() {
    echo "Usage: $0 {install|remove}"
    echo ""
    echo "NetMod OpenWRT Installer v${VERSION}"
    echo "Author: miladjs"
    echo "Repository: https://github.com/miladjs/netmod-openwrt"
    exit 1
}

case "$1" in
    install)
        do_install
        ;;
    remove|uninstall)
        do_remove
        ;;
    *)
        show_usage
        ;;
esac
INSTALL_EOF

chmod +x install.sh
