#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# 1. 环境初始化与全局变量
# ------------------------------------------------------------------------------
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=en_US.UTF-8
set -o pipefail # 管道错误传递

# 颜色
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 目录结构 (保持与原脚本兼容但更规范)
ROOT_DIR="/etc/v2ray-agent"
LOG_FILE="${ROOT_DIR}/install.log"
XRAY_ROOT="${ROOT_DIR}/xray"
XRAY_CONF="${XRAY_ROOT}/conf"
SINGBOX_ROOT="${ROOT_DIR}/sing-box"
SINGBOX_CONF="${SINGBOX_ROOT}/conf"
TLS_DIR="${ROOT_DIR}/tls"
NGINX_CONF="/etc/nginx/conf.d"
NGINX_HTML="/usr/share/nginx/html"
SUBSCRIBE_DIR="${ROOT_DIR}/subscribe"
TMP_DIR="/tmp/v2ray-agent-tmp"

# ------------------------------------------------------------------------------
# 2. 基础工具函数 (Utils)
# ------------------------------------------------------------------------------

log() {
    local level=$1; shift; local msg=$*
    local ts=$(date "+%Y-%m-%d %H:%M:%S")
    case "$level" in
        "INFO") echo -e "${GREEN}[INFO] ${msg}${PLAIN}" ;;
        "WARN") echo -e "${YELLOW}[WARN] ${msg}${PLAIN}" ;;
        "ERROR") echo -e "${RED}[ERROR] ${msg}${PLAIN}" ;;
    esac
    mkdir -p "$ROOT_DIR"
    echo "[$ts][$level] $msg" >> "$LOG_FILE"
}

abort() { log "ERROR" "$1"; exit 1; }

# 依赖检查与安装 (统一适配 Debian/CentOS/Alpine)
install_pkg() {
    local pkg=$1
    if ! command -v "$pkg" >/dev/null 2>&1; then
        log "INFO" "Installing dependency: $pkg"
        if command -v apt-get >/dev/null; then
            apt-get update -y >/dev/null 2>&1 && apt-get install -y "$pkg" >/dev/null 2>&1
        elif command -v yum >/dev/null; then
            yum install -y "$pkg" >/dev/null 2>&1
        elif command -v apk >/dev/null; then
            apk add "$pkg" >/dev/null 2>&1
        else
            abort "Unknown package manager"
        fi
    fi
}

check_sys() {
    [[ $EUID -ne 0 ]] && abort "请使用 root 运行此脚本"
    
    if [ -f /etc/os-release ]; then . /etc/os-release; else abort "OS detect failed"; fi
    
    case "$(uname -m)" in
        'x86_64'|'amd64') ARCH="64"; SBOX_ARCH="amd64" ;;
        'aarch64'|'armv8') ARCH="arm64-v8a"; SBOX_ARCH="arm64" ;;
        *) abort "不支持的架构: $(uname -m)" ;;
    esac

    # 安装基础工具
    local tools=("wget" "curl" "jq" "tar" "unzip" "openssl" "socat" "cron" "lsof" "qrencode")
    for tool in "${tools[@]}"; do install_pkg "$tool"; done
    
    # 创建安全用户
    if ! id "v2ray-agent" >/dev/null 2>&1; then
        useradd -M -s /usr/sbin/nologin v2ray-agent
    fi
    
    mkdir -p "$ROOT_DIR" "$XRAY_CONF" "$SINGBOX_CONF" "$TLS_DIR" "$SUBSCRIBE_DIR" "$TMP_DIR"
    chown -R v2ray-agent:v2ray-agent "$ROOT_DIR"
}

# 健壮的输入读取
read_input() {
    local prompt=$1; local default=$2; local regex=$3; local var_name=$4
    while true; do
        read -r -p "${prompt} [默认: ${default}]: " input
        input=${input:-$default}
        if [[ -n "$regex" && ! "$input" =~ $regex ]]; then
            log "WARN" "格式错误，请重新输入"
        else
            eval $var_name="\"$input\""
            break
        fi
    done
}

# ------------------------------------------------------------------------------
# 3. 核心安装逻辑 (Installation)
# ------------------------------------------------------------------------------

install_xray() {
    log "INFO" "正在安装 Xray-core..."
    local ver=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
    [[ -z "$ver" || "$ver" == "null" ]] && ver="v1.8.4" # Fallback

    local url="https://github.com/XTLS/Xray-core/releases/download/${ver}/Xray-linux-${ARCH}.zip"
    wget -qO "$TMP_DIR/xray.zip" "$url" || abort "下载 Xray 失败"
    
    unzip -o "$TMP_DIR/xray.zip" -d "$XRAY_ROOT" >/dev/null
    chmod +x "$XRAY_ROOT/xray"
    rm "$TMP_DIR/xray.zip"
    
    # 下载 Geo 数据
    wget -qO "$XRAY_ROOT/geosite.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -qO "$XRAY_ROOT/geoip.dat" "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    
    # 赋权
    if command -v setcap >/dev/null; then
        setcap 'cap_net_bind_service=+ep' "$XRAY_ROOT/xray"
    fi
    chown -R v2ray-agent:v2ray-agent "$XRAY_ROOT"

    # Systemd 配置
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=v2ray-agent
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=${XRAY_ROOT}/xray run -confdir ${XRAY_CONF}
Restart=on-failure
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

install_singbox() {
    log "INFO" "正在安装 Sing-box..."
    local ver=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    [[ -z "$ver" || "$ver" == "null" ]] && ver="v1.8.0"

    local url="https://github.com/SagerNet/sing-box/releases/download/${ver}/sing-box-${ver#v}-linux-${SBOX_ARCH}.tar.gz"
    wget -qO "$TMP_DIR/singbox.tar.gz" "$url" || abort "下载 Sing-box 失败"
    
    tar -xzf "$TMP_DIR/singbox.tar.gz" -C "$TMP_DIR"
    mv "$TMP_DIR"/sing-box-*/sing-box "$SINGBOX_ROOT/sing-box"
    chmod +x "$SINGBOX_ROOT/sing-box"
    
    if command -v setcap >/dev/null; then
        setcap 'cap_net_bind_service=+ep' "$SINGBOX_ROOT/sing-box"
    fi
    chown -R v2ray-agent:v2ray-agent "$SINGBOX_ROOT"

    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=Sing-Box Service
After=network.target nss-lookup.target

[Service]
User=v2ray-agent
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=${SINGBOX_ROOT}/sing-box run -c ${SINGBOX_CONF}/config.json
Restart=on-failure
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

install_nginx() {
    log "INFO" "安装 Nginx..."
    install_pkg "nginx"
    systemctl enable nginx
    mkdir -p "$NGINX_CONF" "$NGINX_HTML"
}

# ------------------------------------------------------------------------------
# 4. 证书与域名管理 (TLS & ACME)
# ------------------------------------------------------------------------------

issue_cert() {
    local domain=$1
    if [[ -z "$domain" ]]; then return; fi
    
    if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
        curl https://get.acme.sh | sh -s email=admin@v2ray-agent.com
    fi
    
    systemctl stop nginx
    # 强制申请 ECC 证书
    "$HOME/.acme.sh/acme.sh" --issue -d "$domain" --standalone -k ec-256 --force
    "$HOME/.acme.sh/acme.sh" --installcert -d "$domain" \
        --fullchainpath "$TLS_DIR/${domain}.crt" \
        --keypath "$TLS_DIR/${domain}.key" --ecc
        
    chown -R v2ray-agent:v2ray-agent "$TLS_DIR"
    chmod 644 "$TLS_DIR/${domain}.crt" "$TLS_DIR/${domain}.key"
    systemctl start nginx
}

# ------------------------------------------------------------------------------
# 5. 配置生成工厂 (Config Factory - JQ Implementation)
# ------------------------------------------------------------------------------

# 初始化 Xray 基础配置
init_xray_base() {
    jq -n '{
        log: {loglevel: "warning", error: "/etc/v2ray-agent/xray/error.log"},
        dns: {servers: ["1.1.1.1", "8.8.8.8", "localhost"]},
        routing: {domainStrategy: "IPIfNonMatch", rules: []},
        inbounds: [],
        outbounds: [{protocol: "freedom", tag: "direct"}, {protocol: "blackhole", tag: "block"}]
    }' > "$XRAY_CONF/00_base.json"
}

# 通用 Xray 入站生成器 (取代原脚本的 cat <<EOF)
add_xray_inbound() {
    local tag=$1
    local protocol=$2
    local port=$3
    local uuid=$4
    local path=$5
    local domain=$6
    local type=$7      # tcp, ws, grpc, xhttp
    local security=$8  # tls, reality, none
    local dest_port=$9 # for fallback or reality dest

    local file="$XRAY_CONF/02_inbound_${tag}.json"
    local cert="$TLS_DIR/${domain}.crt"
    local key="$TLS_DIR/${domain}.key"

    # 构建基础 JSON
    local jq_cmd="jq -n \
        --arg tag \"$tag\" \
        --arg port \"$port\" \
        --arg proto \"$protocol\" \
        --arg type \"$type\" \
        --arg sec \"$security\" \
        '{inbounds: [{
            tag: \$tag,
            port: (\$port|tonumber),
            protocol: \$proto,
            settings: {},
            streamSettings: {network: \$type, security: \$sec}
        }]}'"

    # 协议特定配置
    if [[ "$protocol" == "vless" ]]; then
        local flow=""
        [[ "$security" == "tls" && "$type" == "tcp" ]] && flow="xtls-rprx-vision"
        [[ "$security" == "reality" && "$type" == "tcp" ]] && flow="xtls-rprx-vision"
        
        jq_cmd+=" | .inbounds[0].settings = {clients: [{id: \"$uuid\", flow: \"$flow\"}], decryption: \"none\"}"
        
        # Fallback 逻辑 (VLESS TCP XTLS -> Nginx/Trojan)
        if [[ "$flow" == "xtls-rprx-vision" ]]; then
            jq_cmd+=" | .inbounds[0].settings.fallbacks = [
                {dest: 31300, xver: 1}, 
                {alpn: \"h2\", dest: 31302, xver: 1}
            ]"
        fi
    elif [[ "$protocol" == "vmess" ]]; then
        jq_cmd+=" | .inbounds[0].settings.clients = [{id: \"$uuid\", alterId: 0}]"
    elif [[ "$protocol" == "trojan" ]]; then
        jq_cmd+=" | .inbounds[0].settings.clients = [{password: \"$uuid\"}]"
    fi

    # 传输层配置
    if [[ "$type" == "ws" ]]; then
        jq_cmd+=" | .inbounds[0].streamSettings.wsSettings = {path: \"$path\"}"
    elif [[ "$type" == "grpc" ]]; then
        jq_cmd+=" | .inbounds[0].streamSettings.grpcSettings = {serviceName: \"$path\"}"
    elif [[ "$type" == "xhttp" ]]; then
        jq_cmd+=" | .inbounds[0].streamSettings.xhttpSettings = {path: \"$path\"}"
    fi

    # 安全层配置
    if [[ "$security" == "tls" ]]; then
        jq_cmd+=" | .inbounds[0].streamSettings.tlsSettings = {
            certificates: [{certificateFile: \"$cert\", keyFile: \"$key\"}],
            alpn: [\"h2\", \"http/1.1\"]
        }"
    elif [[ "$security" == "reality" ]]; then
        # 自动生成 Reality Key
        local keys=$($XRAY_ROOT/xray x25519)
        local pk=$(echo "$keys" | grep "Private" | awk '{print $3}')
        local pub=$(echo "$keys" | grep "Public" | awk '{print $3}')
        local sid=$(openssl rand -hex 8)
        
        # 保存用于订阅
        echo "$pub" > "$ROOT_DIR/reality_pub.key"
        echo "$sid" > "$ROOT_DIR/reality_sid.key"
        
        jq_cmd+=" | .inbounds[0].streamSettings.realitySettings = {
            show: false,
            dest: \"$domain:443\",
            xver: 0,
            serverNames: [\"$domain\"],
            privateKey: \"$pk\",
            shortIds: [\"$sid\"]
        }"
    fi

    eval "$jq_cmd" > "$file"
}

# Sing-box 配置生成 (Hysteria2 / Tuic / Naive)
gen_singbox_inbound() {
    local type=$1
    local port=$2
    local auth=$3
    local domain=$4
    local cert="$TLS_DIR/${domain}.crt"
    local key="$TLS_DIR/${domain}.key"
    
    # 确保基础结构存在
    if [ ! -f "$SINGBOX_CONF/config.json" ]; then
        jq -n '{log: {level: "info"}, inbounds: [], outbounds: [{type: "direct"}]}' > "$SINGBOX_CONF/config.json"
    fi
    
    local inbound=""
    if [[ "$type" == "hysteria2" ]]; then
        inbound=$(jq -n --arg port "$port" --arg pass "$auth" --arg cert "$cert" --arg key "$key" '{
            type: "hysteria2",
            listen: "::",
            listen_port: ($port|tonumber),
            users: [{password: $pass}],
            tls: {enabled: true, certificate_path: $cert, key_path: $key}
        }')
    elif [[ "$type" == "tuic" ]]; then
        inbound=$(jq -n --arg port "$port" --arg uuid "$auth" --arg cert "$cert" --arg key "$key" '{
            type: "tuic",
            listen: "::",
            listen_port: ($port|tonumber),
            users: [{uuid: $uuid}],
            congestion_control: "bbr",
            tls: {enabled: true, certificate_path: $cert, key_path: $key, alpn: ["h3"]}
        }')
    fi
    
    # 动态追加到数组
    local tmp=$(cat "$SINGBOX_CONF/config.json")
    echo "$tmp" | jq ".inbounds += [$inbound]" > "$SINGBOX_CONF/config.json"
}

# ------------------------------------------------------------------------------
# 6. 高级网络功能 (Routing, Firewall, Port Hopping)
# ------------------------------------------------------------------------------

# 端口跳跃 (Port Hopping) 实现
configure_port_hopping() {
    local start=$1
    local end=$2
    local target=$3
    
    if command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-forward-port=port=${start}-${end}:proto=udp:toport=${target}
        firewall-cmd --reload
    elif command -v iptables >/dev/null; then
        iptables -t nat -A PREROUTING -p udp --dport ${start}:${end} -j DNAT --to-destination :${target}
        # 持久化需要 iptables-save，这里略过复杂持久化逻辑
    fi
    log "INFO" "Port hopping configured: $start-$end -> $target"
}

# BT 下载拦截
configure_block_bt() {
    # 使用 JQ 向 Xray 路由添加规则
    local tmp=$(cat "$XRAY_CONF/00_base.json")
    echo "$tmp" | jq '.routing.rules += [{
        type: "field",
        protocol: ["bittorrent"],
        outboundTag: "block"
    }]' > "$XRAY_CONF/00_base.json"
}

# 伪装站下载
download_camouflage() {
    log "INFO" "部署伪装站点..."
    rm -rf "${NGINX_HTML}"/*
    # 使用原脚本的随机模版源
    local random_num=$((RANDOM % 9 + 1))
    local url="https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${random_num}.zip"
    wget -qO "$TMP_DIR/site.zip" "$url"
    unzip -o "$TMP_DIR/site.zip" -d "$NGINX_HTML" >/dev/null 2>&1
    rm "$TMP_DIR/site.zip"
}

# ------------------------------------------------------------------------------
# 7. 主流程控制 (Workflows)
# ------------------------------------------------------------------------------

install_all_in_one() {
    check_sys
    install_nginx
    install_xray
    install_singbox
    
    # 交互配置
    read_input "请输入您的域名" "" "" DOMAIN
    read_input "请输入UUID (回车自动生成)" "" "" UUID
    [[ -z "$UUID" ]] && UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # 申请证书
    issue_cert "$DOMAIN"
    
    # 初始化配置
    init_xray_base
    rm -f "$SINGBOX_CONF/config.json" # Reset Sing-box
    
    # -------------------------------------------------
    # 配置 Xray 协议集 (443端口多路复用)
    # -------------------------------------------------
    # 1. VLESS+XTLS-Vision (监听 443)
    add_xray_inbound "vless_vision" "vless" "443" "$UUID" "" "$DOMAIN" "tcp" "tls"
    
    # 2. VMess+WS (路径 /vws) - 配合 Nginx
    add_xray_inbound "vmess_ws" "vmess" "10001" "$UUID" "/vws" "$DOMAIN" "ws" "none"
    
    # 3. Trojan+gRPC (Service: tgrpc)
    add_xray_inbound "trojan_grpc" "trojan" "10002" "$UUID" "tgrpc" "$DOMAIN" "grpc" "none"
    
    # 4. Reality (监听 8443)
    add_xray_inbound "vless_reality" "vless" "8443" "$UUID" "" "addons.mozilla.org" "tcp" "reality"
    
    # -------------------------------------------------
    # 配置 Sing-box 协议集
    # -------------------------------------------------
    # 1. Hysteria2 (监听 10003)
    gen_singbox_inbound "hysteria2" "10003" "$UUID" "$DOMAIN"
    
    # 2. Tuic (监听 10004)
    gen_singbox_inbound "tuic" "10004" "$UUID" "$DOMAIN"
    
    # -------------------------------------------------
    # 配置 Nginx 前置 (Fallback & Reverse Proxy)
    # -------------------------------------------------
    download_camouflage
    
    cat > "$NGINX_CONF/v2ray-agent.conf" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

# Xray Fallback Handler (HTTP/1.1)
server {
    listen 127.0.0.1:31300 proxy_protocol;
    server_name ${DOMAIN};
    root ${NGINX_HTML};
    index index.html;
    
    # VMess WS 转发
    location /vws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

# Xray Fallback Handler (H2)
server {
    listen 127.0.0.1:31302 http2 proxy_protocol;
    server_name ${DOMAIN};
    
    # Trojan gRPC 转发
    location /tgrpc {
        grpc_pass grpc://127.0.0.1:10002;
    }
}
EOF

    # 权限修正 & 重启
    chown -R v2ray-agent:v2ray-agent "$ROOT_DIR"
    systemctl restart nginx xray sing-box
    
    # -------------------------------------------------
    # 输出账号信息
    # -------------------------------------------------
    local ip=$(curl -s https://ip.sb)
    local reality_pk=$(grep "Private" <<< "$($XRAY_ROOT/xray x25519 -i $(cat $ROOT_DIR/reality_pub.key) 2>&1)" || echo "Check Config")
    local reality_sid=$(cat $ROOT_DIR/reality_sid.key 2>/dev/null)
    
    clear
    echo -e "${GREEN}========== 安装完成 (v4.5.0) ==========${PLAIN}"
    echo -e "域名: ${DOMAIN}"
    echo -e "UUID: ${UUID}"
    echo -e "-----------------------------------------"
    echo -e "${YELLOW}[Xray] VLESS Vision:${PLAIN}   Port 443 (TCP+TLS)"
    echo -e "${YELLOW}[Xray] VMess WS:${PLAIN}       Path /vws (Port 443 Nginx->10001)"
    echo -e "${YELLOW}[Xray] Trojan gRPC:${PLAIN}    Service tgrpc (Port 443 Nginx->10002)"
    echo -e "${YELLOW}[Xray] REALITY:${PLAIN}        Port 8443 (TCP)"
    echo -e "   -> ShortId: ${reality_sid}"
    echo -e "-----------------------------------------"
    echo -e "${BLUE}[SBox] Hysteria2:${PLAIN}      Port 10003 (UDP)"
    echo -e "${BLUE}[SBox] Tuic V5:${PLAIN}        Port 10004 (UDP)"
    echo -e "-----------------------------------------"
    echo -e "配置文件: ${ROOT_DIR}"
}

# ------------------------------------------------------------------------------
# 8. 菜单入口
# ------------------------------------------------------------------------------

menu() {
    clear
    echo -e "${GREEN}v2ray-agent 优化重构版 (Ultimte)${PLAIN}"
    echo -e "-----------------------------------------"
    echo -e "1. 安装/重置所有服务 (推荐)"
    echo -e "2. 仅更新核心组件 (Xray/Sing-box)"
    echo -e "3. 查看账号配置信息"
    echo -e "4. 管理：Hysteria2 端口跳跃"
    echo -e "5. 管理：开启 BT 下载拦截"
    echo -e "6. 卸载脚本"
    echo -e "0. 退出"
    echo -e "-----------------------------------------"
    read -p "请选择: " choice
    
    case $choice in
        1) install_all_in_one ;;
        2) install_xray; install_singbox; echo "核心已更新";;
        3) cat "$LOG_FILE" | grep "UUID" || echo "请先安装";;
        4) 
            read_input "起始端口" "20000" "^[0-9]+$" start
            read_input "结束端口" "30000" "^[0-9]+$" end
            read_input "目标端口(Hysteria2)" "10003" "^[0-9]+$" target
            configure_port_hopping "$start" "$end" "$target"
            ;;
        5) configure_block_bt; systemctl restart xray; echo "BT 拦截已开启" ;;
        6) 
            systemctl stop xray sing-box nginx
            systemctl disable xray sing-box
            rm -rf "$ROOT_DIR" /etc/systemd/system/xray.service /etc/systemd/system/sing-box.service
            systemctl daemon-reload
            userdel v2ray-agent
            echo "卸载完成"
            ;;
        0) exit 0 ;;
        *) menu ;;
    esac
}

# CLI支持
if [[ "$1" == "install" ]]; then
    install_all_in_one
else
    menu
fi
