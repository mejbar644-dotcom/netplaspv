#!/usr/bin/env bash

set -uo pipefail

IFACE="awg0"
CFG_DIR="/etc/amnezia/amneziawg"
CFG="${CFG_DIR}/${IFACE}.conf"
META="${CFG_DIR}/${IFACE}.meta"
FR_ADDR="10.0.0.1"
CIDR="24"
TOKEN_VER="v6.7"
SVC="/etc/systemd/system/udp2raw.service"
ROT_CONF="${CFG_DIR}/rotate.conf"
ROT_BIN="/usr/local/bin/awg-port-rotate.sh"
ROT_DEFAULT_POOL="8443,2053,2083,2087,2096"
NOTRACK_BIN="/usr/local/bin/u2r-notrack.sh"
RPS_BIN="/usr/local/bin/awg-rps.sh"
GUARD_RET='-p tcp -m connbytes --connbytes 11: --connbytes-mode packets --connbytes-dir original -j RETURN'
HELPERS_CHANGED=0
NOTICE=""

# Auto-detect the current SSH port so it is never forwarded or blocked
DETECTED_SSH=$(ss -tlpn 2>/dev/null | grep sshd | awk '{print $4}' | awk -F':' '{print $NF}' | head -n1)
KEEP_TCP_PORTS="${DETECTED_SSH:-22},80,443,10052"

# ---------- Colors & output ----------
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
  CYAN=$(tput setaf 6); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
  RED=$(tput setaf 1); BOLD=$(tput bold); RESET=$(tput sgr0)
  DIM=$(tput dim 2>/dev/null || true)
else
  CYAN=""; YELLOW=""; GREEN=""; RED=""; BOLD=""; RESET=""; DIM=""
fi
info()  { echo "${CYAN}[*]${RESET} $*"; }
ok()    { echo "${GREEN}[+]${RESET} $*"; }
warn()  { echo "${YELLOW}[!]${RESET} $*"; }
err()   { echo "${RED}[x]${RESET} $*" >&2; }
die()   { err "$*"; exit 1; }

banner() {
  clear 2>/dev/null || true
  echo "${CYAN}${BOLD}"
  cat <<'ART'
 _   _ _____ _____ ____  _        _    ____
| \ | | ____|_   _|  _ \| |      / \  / ___|
|  \| |  _|   | | | |_) | |     / _ \ \___ \
| |\  | |___  | | |  __/| |___ / ___ \ ___) |
|_| \_|_____| |_| |_|   |_____/_/   \_\____/
ART
  echo "${RESET}${BOLD}  AmneziaWG + udp2raw FakeTCP Tunnel  |  v7.0  |  Netplas Team${RESET}"
  echo "${DIM}  Multi-Iran hub: 1 foreign server + up to 5 Iran nodes${RESET}"
  echo
}

[[ $EUID -eq 0 ]] || die "Please run this script as root (sudo -i)."

exec 9>/var/lock/awg-tunnel.lock
flock -n 9 || die "Another instance of this script is already running."

# ---------- Helpers ----------
rnd() {
  local min=$1 max=$2 span=$(( $2 - $1 + 1 ))
  echo $(( min + ( $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % span ) ))
}

port_in_use() {
  ss -tuln 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${1}$"
}

rnd_free_port() {
  local min=$1 max=$2 p
  while true; do
    p=$(rnd "$min" "$max")
    port_in_use "$p" || { echo "$p"; return 0; }
  done
}

valid_ipv4() {
  local o
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -ra o <<< "$1"
  for x in "${o[@]}"; do (( 10#$x <= 255 )) || return 1; done
  return 0
}

confirm_yes() {
  local a
  read -rp "$1 [Y/n]: " a
  [[ "${a,,}" != "n" ]]
}

# Writes stdin to DEST only if it differs; returns 0 when the file changed
sync_file() {
  local dest=$1 mode=${2:-644} tmp
  tmp=$(mktemp) || return 1
  cat > "$tmp"
  if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    return 1
  fi
  install -m "$mode" "$tmp" "$dest"
  rm -f "$tmp"
  return 0
}

normalize_pool() {
  echo "$1" | tr -d ' ' | tr ',' '\n' | grep -E '^[0-9]+$' | sort -nu | paste -sd, -
}

valid_pool() {
  local p n=0 arr
  [[ -n "$1" ]] || return 1
  IFS=',' read -ra arr <<< "$1"
  for p in "${arr[@]}"; do
    valid_port "$p" || return 1
    n=$(( n + 1 ))
  done
  (( n >= 2 ))
}

port_used_by_other() {
  ss -tlnp 2>/dev/null | awk -v p="$1" 'NR>1 {n=split($4,a,":"); if (a[n]==p) print}' | grep -qv 'udp2raw'
}

filter_free_pool() {
  local p arr out=()
  IFS=',' read -ra arr <<< "$1"
  for p in "${arr[@]}"; do
    if port_used_by_other "$p"; then
      warn "Port ${p} is used by another service and was removed from the pool." >&2
    else
      out+=("$p")
    fi
  done
  ( IFS=,; echo "${out[*]:-}" )
}

# Rotation day number; it flips 10 seconds before 04:30 Tehran so the 04:30 run always sees the new day
rot_day() {
  echo $(( ( $(date +%s) - 3590 ) / 86400 ))
}

# Pick the day's port from the pool and the shared secret
rot_pick_port() {
  local pool=$1 secret=$2 off=${3:-0} arr n eday h0
  IFS=',' read -ra arr <<< "$pool"
  n=${#arr[@]}
  (( n > 0 )) || return 1
  eday=$(( $(rot_day) + off ))
  h0=$(( 16#$(printf '%s' "$secret" | sha256sum | cut -c1-8) ))
  echo "${arr[$(( (h0 + eday) % n ))]}"
}

cur_port_from_service() {
  if grep -q ' -s ' "$SVC" 2>/dev/null; then
    grep -oE -- '-l 0\.0\.0\.0:[0-9]+' "$SVC" | grep -oE '[0-9]+$'
  else
    grep -oE -- '-r [0-9.]+:[0-9]+' "$SVC" | grep -oE '[0-9]+$'
  fi
}

svc_secret() {
  sed -n 's/.* -k "\([^"]*\)".*/\1/p' "$SVC" 2>/dev/null | head -n1
}

write_rotate_conf() {
  mkdir -p "$CFG_DIR"; chmod 700 "$CFG_DIR"
  { echo "POOL=$1"; echo "SECRET=$2"; echo "APPLIED=$(rot_day)"; } > "$ROT_CONF"
  chmod 600 "$ROT_CONF"
}

multiport_chunks() {
  local tok slots cur="" n=0 arr
  IFS=',' read -ra arr <<< "$1"
  for tok in "${arr[@]}"; do
    [[ -n "$tok" ]] || continue
    slots=1; [[ "$tok" == *:* ]] && slots=2
    if (( n + slots > 15 )); then echo "$cur"; cur=""; n=0; fi
    cur+="${cur:+,}${tok}"
    n=$(( n + slots ))
  done
  [[ -n "$cur" ]] && echo "$cur"
  return 0
}

valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

gen_pass() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

main_iface() {
  ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}'
}

pub_ip() { curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true; }

meta_get() {
  [[ -f "$META" ]] || return 0
  sed -n "s/^$1=//p" "$META" | head -n1
}

confirm() {
  local a
  read -rp "$1 [y/N]: " a
  [[ "${a,,}" == "y" ]]
}

open_ufw_tcp() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$1/tcp" >/dev/null 2>&1 && ok "ufw: TCP port $1 allowed."
  fi
}

close_ufw_tcp() {
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw --force delete allow "$1/tcp" >/dev/null 2>&1 && ok "ufw: old TCP port $1 closed."
  fi
}

refresh_meta_token() {
  [[ "$(meta_get ROLE)" == "foreign" ]] || return 0
  (
    local t cur nt
    t=$(meta_get TOKEN); [[ -n "$t" ]] || exit 0
    decode_token "$t"
    cur=$(cur_port_from_service); [[ -n "$cur" ]] && RAW_PORT="$cur"
    ROT_POOL=$(sed -n 's/^POOL=//p' "$ROT_CONF" 2>/dev/null | head -n1)
    nt=$(encode_token)
    sed -i "s|^RAW_PORT=.*|RAW_PORT=${RAW_PORT}|; s|^TOKEN=.*|TOKEN=${nt}|" "$META"
  )
}

apply_awg_live() {
  set -a; . /etc/default/amneziawg 2>/dev/null || true; set +a
  if ! awg syncconf "$IFACE" <(awg-quick strip "$IFACE") 2>/dev/null; then
    awg-quick down "$IFACE" >/dev/null 2>&1 || true
    awg-quick up "$IFACE" || die "Restart failed."
  fi
}

# ---------- Prerequisites ----------
detect_os() {
  . /etc/os-release 2>/dev/null || true
  OS_ID="${ID:-unknown}"
}

install_tools() {
  detect_os
  info "Installing system prerequisites & kernel headers..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl wget git iptables iproute2 openresolv tar conntrack psmisc net-tools \
      software-properties-common ca-certificates build-essential \
      "linux-headers-$(uname -r)" >/dev/null 2>&1 || \
  apt-get install -y -qq curl wget git iptables iproute2 tar conntrack psmisc net-tools \
      software-properties-common ca-certificates build-essential >/dev/null 2>&1

  apt-get install -y -qq tzdata >/dev/null 2>&1 || true
  timedatectl set-ntp true >/dev/null 2>&1 || true

  if [[ "$OS_ID" == "ubuntu" ]]; then
    add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
    apt-get update -qq
    apt-get install -y -qq amneziawg amneziawg-tools >/dev/null 2>&1 || true
  fi

  if ! command -v awg >/dev/null 2>&1; then
    warn "Building amneziawg-tools from source..."
    rm -rf /tmp/awg-tools
    git clone -q --depth 1 https://github.com/amnezia-vpn/amneziawg-tools /tmp/awg-tools \
      || die "Cannot fetch amneziawg-tools."
    make -s -C /tmp/awg-tools/src -j"$(nproc)" >/dev/null \
      && make -s -C /tmp/awg-tools/src install >/dev/null \
      || die "Build of amneziawg-tools failed."
  fi
  ok "amneziawg-tools is ready."
}

install_udp2raw() {
  if command -v udp2raw >/dev/null 2>&1; then
    ok "udp2raw is already installed."
    return 0
  fi
  info "Downloading and installing udp2raw..."
  mkdir -p /tmp/udp2raw
  wget -q --tries=3 --timeout=15 https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz -O /tmp/udp2raw/udp2raw.tar.gz \
    || die "Failed to download udp2raw."
  tar -xzf /tmp/udp2raw/udp2raw.tar.gz -C /tmp/udp2raw

  local bin="udp2raw_amd64"
  case "$(uname -m)" in
    aarch64|arm64) bin="udp2raw_arm" ;;
  esac
  [[ -f "/tmp/udp2raw/${bin}" ]] || die "udp2raw binary ${bin} not found in archive."
  cp "/tmp/udp2raw/${bin}" /usr/local/bin/udp2raw
  chmod +x /usr/local/bin/udp2raw
  rm -rf /tmp/udp2raw
  ok "udp2raw installed successfully."
}

kernel_ok() {
  modprobe amneziawg >/dev/null 2>&1
  ip link add dev awgtest type amneziawg >/dev/null 2>&1 || return 1
  ip link del awgtest >/dev/null 2>&1
  return 0
}

install_userspace() {
  command -v amneziawg-go >/dev/null 2>&1 && { ok "amneziawg-go already installed."; return 0; }
  warn "Kernel module unavailable. Building amneziawg-go userspace..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq golang-go >/dev/null 2>&1 || apt-get install -y -qq golang >/dev/null 2>&1
  command -v go >/dev/null 2>&1 || die "Go toolchain not available."
  rm -rf /tmp/awg-go
  git clone -q --depth 1 https://github.com/amnezia-vpn/amneziawg-go /tmp/awg-go \
    || die "Cannot fetch amneziawg-go."
  ( cd /tmp/awg-go && go build -o /usr/local/bin/amneziawg-go . ) >/dev/null 2>&1 \
    || die "Build of amneziawg-go failed."
  chmod +x /usr/local/bin/amneziawg-go
  [[ -e /dev/net/tun ]] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200 2>/dev/null; chmod 600 /dev/net/tun; }
  ok "amneziawg-go installed."
}

setup_backend() {
  if kernel_ok; then
    ok "Kernel module 'amneziawg' is active."
    echo "amneziawg" > /etc/modules-load.d/amneziawg.conf
    USERSPACE=0
  else
    install_userspace
    USERSPACE=1
  fi
  mkdir -p /etc/default
  if [[ $USERSPACE -eq 1 ]]; then
    cat > /etc/default/amneziawg <<'EOF'
WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
AWG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
WG_SUDO=1
EOF
  else
    : > /etc/default/amneziawg
  fi
}

# ---------- Kernel, NIC queue & conntrack tuning ----------
gen_sysctl_conf() {
  cat <<'EOF'
# IP Forwarding & RP Filter
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# BBR & Queue Discipline
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Socket & Network Buffers
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# RPS flow table (used by awg-rps.service to spread softirq over all CPUs)
net.core.rps_sock_flow_entries = 32768

# TCP FastOpen, Keepalive & MTU Probing
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65535

# Conntrack
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120
net.netfilter.nf_conntrack_acct = 1

# File Descriptors
fs.file-max = 2097152
EOF
}

gen_limits_conf() {
  cat <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
}

# ---------- RPS (spread network softirq over all CPUs) ----------
gen_rps_script() {
  cat <<'EOF'
#!/usr/bin/env bash
# Spread RX softirq work of a single-queue NIC across all CPUs (RPS).
NIC=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
[[ -n "$NIC" && -d "/sys/class/net/$NIC/queues" ]] || exit 0
N=$(nproc)
(( N > 1 )) || exit 0
(( N > 32 )) && N=32
Q=$(ls -d /sys/class/net/$NIC/queues/rx-* 2>/dev/null | wc -l)
(( Q > 0 )) || exit 0
# A multi-queue NIC already spreads load in hardware; RPS would only add overhead
(( Q >= N )) && exit 0
MASK=$(printf '%x' $(( (1 << N) - 1 )))
CNT=$(( 32768 / Q ))
sysctl -qw net.core.rps_sock_flow_entries=32768 2>/dev/null || true
for q in /sys/class/net/$NIC/queues/rx-*; do
  echo "$MASK" > "$q/rps_cpus" 2>/dev/null || true
  echo "$CNT" > "$q/rps_flow_cnt" 2>/dev/null || true
done
exit 0
EOF
}

gen_rps_service() {
  cat <<EOF
[Unit]
Description=RPS softirq spreading for the AWG tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${RPS_BIN}

[Install]
WantedBy=multi-user.target
EOF
}

ensure_rps() {
  local ch=0
  gen_rps_script | sync_file "$RPS_BIN" 755 && ch=1
  gen_rps_service | sync_file /etc/systemd/system/awg-rps.service 644 && ch=1
  if (( ch )); then
    HELPERS_CHANGED=1
    systemctl daemon-reload
    systemctl enable awg-rps.service >/dev/null 2>&1
    systemctl restart awg-rps.service >/dev/null 2>&1
  else
    systemctl enable --now awg-rps.service >/dev/null 2>&1 || true
  fi
  return 0
}

sysctl_tuning() {
  info "Applying kernel, BBR, socket buffer, NIC queue & conntrack optimizations..."
  modprobe nf_conntrack >/dev/null 2>&1 || true
  modprobe tcp_bbr >/dev/null 2>&1 || true

  gen_sysctl_conf | sync_file /etc/sysctl.d/99-awg-optimizer.conf 644

  sysctl -q --system >/dev/null 2>&1 || true

  if [[ -f /sys/module/nf_conntrack/parameters/hashsize ]]; then
    echo 524288 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
  fi

  local DEF_NIC; DEF_NIC=$(main_iface)
  if [[ -n "$DEF_NIC" ]]; then
    ip link set dev "$DEF_NIC" txqueuelen 10000 2>/dev/null || true
  fi

  gen_limits_conf | sync_file /etc/security/limits.d/99-awg.conf 644
  ensure_rps
  ok "Kernel, NIC queue (10000), RPS & conntrack optimizations applied."
}

# ---------- Obfuscation profile & token ----------
gen_profile() {
  JC=$(rnd 3 6)
  JMIN=$(rnd 40 80)
  JMAX=$(rnd $((JMIN + 50)) 500)
  S1=$(rnd 20 110)
  S2=$(rnd 20 110)
  while [[ $((S1 + 56)) -eq $S2 ]]; do S2=$(rnd 20 110); done
  S3=$(rnd 10 45)
  S4=$(rnd 10 25)
  H1=$(rnd 100000 2147483000); H2=$(rnd 100000 2147483000)
  H3=$(rnd 100000 2147483000); H4=$(rnd 100000 2147483000)
  while [[ "$H2" == "$H1" ]]; do H2=$(rnd 100000 2147483000); done
  while [[ "$H3" == "$H1" || "$H3" == "$H2" ]]; do H3=$(rnd 100000 2147483000); done
  while [[ "$H4" == "$H1" || "$H4" == "$H2" || "$H4" == "$H3" ]]; do H4=$(rnd 100000 2147483000); done
}

encode_token() {
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$TOKEN_VER" "$FOREIGN_IP" "$AWG_PORT" "$RAW_PORT" "$RAW_PASS" "$FR_PUB" "$PSK" \
    "$JC" "$JMIN" "$JMAX" "$S1" "$S2" "$S3" "$S4" "$H1" "$H2" "$H3" "$H4" "${ROT_POOL:-}" \
    | base64 -w0
}

decode_token() {
  local raw; raw=$(echo "$1" | tr -d ' \n\r' | base64 -d 2>/dev/null) || die "Invalid token."
  IFS='|' read -r V FOREIGN_IP AWG_PORT RAW_PORT RAW_PASS FR_PUB PSK JC JMIN JMAX S1 S2 S3 S4 H1 H2 H3 H4 ROT_POOL <<< "$raw"
  [[ "$V" == "v6.7" || "$V" == "v6.5" || "$V" == "v6.4" || "$V" == "v6.0" || "$V" == "v5.0" ]] || die "Token version mismatch."
  [[ -n "$FR_PUB" && -n "$RAW_PORT" && -n "$RAW_PASS" ]] || die "Token is incomplete."
  valid_ipv4 "$FOREIGN_IP" || die "Token has an invalid foreign IP."
  valid_port "$RAW_PORT" || die "Token has an invalid port."
}

# ---------- FakeTCP notrack (keeps the outer FakeTCP packets out of conntrack) ----------
gen_notrack_script() {
  cat <<'EOF'
#!/usr/bin/env bash
# Adds/removes raw-table NOTRACK rules for the udp2raw FakeTCP port.
# The port is read from the udp2raw unit, so it follows daily port rotation.
SVC="/etc/systemd/system/udp2raw.service"
ST="/run/u2r-notrack.rules"

rules_for() {
  if grep -q ' -s ' "$SVC"; then
    local p
    p=$(grep -oE -- '-l 0\.0\.0\.0:[0-9]+' "$SVC" | grep -oE '[0-9]+$')
    [[ -n "$p" ]] || return 1
    echo "PREROUTING -p tcp --dport $p"
    echo "OUTPUT -p tcp --sport $p"
  else
    local r ip p
    r=$(grep -oE -- '-r [0-9.]+:[0-9]+' "$SVC" | awk '{print $2}')
    [[ -n "$r" ]] || return 1
    ip=${r%:*}; p=${r#*:}
    echo "PREROUTING -p tcp -s $ip --sport $p"
    echo "OUTPUT -p tcp -d $ip --dport $p"
  fi
}

del() {
  [[ -f "$ST" ]] || return 0
  while read -r l; do
    [[ -n "$l" ]] && iptables -t raw -D $l -j CT --notrack 2>/dev/null
  done < "$ST"
  rm -f "$ST"
  return 0
}

add() {
  del
  rules_for > "$ST" || { rm -f "$ST"; return 0; }
  while read -r l; do
    [[ -n "$l" ]] || continue
    iptables -t raw -C $l -j CT --notrack 2>/dev/null || iptables -t raw -A $l -j CT --notrack 2>/dev/null
  done < "$ST"
  return 0
}

case "${1:-}" in
  add) add ;;
  del) del ;;
esac
exit 0
EOF
}

write_notrack_helper() {
  gen_notrack_script | sync_file "$NOTRACK_BIN" 755 && HELPERS_CHANGED=1
  return 0
}

# Adds the hooks to an existing udp2raw unit (installs made by older script versions)
ensure_notrack_in_service() {
  write_notrack_helper
  [[ -f "$SVC" ]] || return 0
  if ! grep -q 'u2r-notrack' "$SVC"; then
    sed -i "/^ExecStart=/i ExecStartPre=-${NOTRACK_BIN} add" "$SVC"
    sed -i "/^Restart=always/i ExecStopPost=-${NOTRACK_BIN} del" "$SVC"
    HELPERS_CHANGED=1
    systemctl daemon-reload
  fi
  # Applies instantly without restarting the tunnel
  "$NOTRACK_BIN" add
  return 0
}

# ---------- Anti-SNI guard: skip the string scan after the first 10 packets ----------
migrate_guard_rule() {
  [[ "$(meta_get ROLE)" == "iran" && -f "$CFG" ]] || return 0
  grep -q 'connbytes' "$CFG" || return 0
  if ! grep -q 'connbytes 11:' "$CFG"; then
    cp -a "$CFG" "${CFG}.bak"
    sed -i "/AWG_GUARD -p tcp -m multiport --dports 25,465,587 -j DROP/a PostUp = iptables -A AWG_GUARD ${GUARD_RET} 2>/dev/null || true" "$CFG"
    grep -q 'connbytes 11:' "$CFG" && HELPERS_CHANGED=1
  fi
  if iptables -n -L AWG_GUARD >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    iptables -C AWG_GUARD $GUARD_RET 2>/dev/null || iptables -I AWG_GUARD 2 $GUARD_RET 2>/dev/null || true
  fi
  return 0
}

# ---------- udp2raw services ----------
setup_udp2raw_foreign() {
  systemctl stop udp2raw.service >/dev/null 2>&1 || true
  if ss -tlpn 2>/dev/null | grep -q ":${RAW_PORT} "; then
    warn "Port ${RAW_PORT} is currently in use by another process."
    if confirm "Force-free port ${RAW_PORT}?"; then
      fuser -k "${RAW_PORT}/tcp" >/dev/null 2>&1 || true
      sleep 1
    else
      die "Re-run and choose a free port for FakeTCP."
    fi
  fi

  write_notrack_helper
  cat > /etc/systemd/system/udp2raw.service <<EOF
[Unit]
Description=udp2raw FakeTCP Server (Foreign Multi-Iran Hub)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
ExecStartPre=-${NOTRACK_BIN} add
ExecStart=/usr/local/bin/udp2raw -s -l 0.0.0.0:${RAW_PORT} -r 127.0.0.1:${AWG_PORT} -k "${RAW_PASS}" --raw-mode faketcp -a --keep-rule --fix-gro --cipher-mode aes128cbc --auth-mode hmac_sha1 --seq-mode 4 --log-level 1
ExecStopPost=-${NOTRACK_BIN} del
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now udp2raw.service >/dev/null 2>&1
  sleep 1
  if systemctl is-active --quiet udp2raw.service; then
    ok "udp2raw FakeTCP hub active on TCP ${RAW_PORT} -> local AWG UDP ${AWG_PORT}."
  else
    err "udp2raw failed to start. Check port ${RAW_PORT}."
  fi
  open_ufw_tcp "$RAW_PORT"
}

setup_udp2raw_iran() {
  systemctl stop udp2raw.service >/dev/null 2>&1 || true
  write_notrack_helper
  cat > /etc/systemd/system/udp2raw.service <<EOF
[Unit]
Description=udp2raw FakeTCP Client (Iran Node #${NODE_ID})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
ExecStartPre=-${NOTRACK_BIN} add
ExecStart=/usr/local/bin/udp2raw -c -l 127.0.0.1:${LOCAL_UDP_PORT} -r ${FOREIGN_IP}:${RAW_PORT} -k "${RAW_PASS}" --raw-mode faketcp -a --keep-rule --fix-gro --cipher-mode aes128cbc --auth-mode hmac_sha1 --seq-mode 4 --log-level 1
ExecStopPost=-${NOTRACK_BIN} del
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now udp2raw.service >/dev/null 2>&1
  sleep 2
  if systemctl is-active --quiet udp2raw.service; then
    ok "udp2raw FakeTCP client active on 127.0.0.1:${LOCAL_UDP_PORT} -> ${FOREIGN_IP}:${RAW_PORT}."
  else
    err "udp2raw client failed to start."
  fi
}

# ---------- Watchdog & nightly rotation ----------
gen_watchdog_script() {
  cat <<EOF
#!/usr/bin/env bash
TARGET_IP="${FR_ADDR}"
IFACE="${IFACE}"

if ping -c 3 -W 2 "\$TARGET_IP" >/dev/null 2>&1; then
  exit 0
fi

logger -t awg-watchdog "Ping to \$TARGET_IP failed. Step 1: syncing rotation port & restarting udp2raw..."
${ROT_BIN} >/dev/null 2>&1 || true
systemctl restart udp2raw.service
sleep 6

if ping -c 3 -W 2 "\$TARGET_IP" >/dev/null 2>&1; then
  logger -t awg-watchdog "Tunnel recovered after udp2raw restart."
  exit 0
fi

logger -t awg-watchdog "Still down. Step 2: restarting awg-quick@\$IFACE..."
systemctl restart "awg-quick@\${IFACE}.service"
EOF
}

write_watchdog_script() {
  gen_watchdog_script | sync_file /usr/local/bin/awg-watchdog.sh 755 && HELPERS_CHANGED=1
  return 0
}

gen_watchdog_service() {
  cat <<'EOF'
[Unit]
Description=AmneziaWG Self-Healing Watchdog Check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/awg-watchdog.sh
EOF
}

gen_watchdog_timer() {
  cat <<'EOF'
[Unit]
Description=Run AmneziaWG Watchdog every 45 seconds

[Timer]
OnBootSec=60
OnUnitActiveSec=45
AccuracySec=5

[Install]
WantedBy=timers.target
EOF
}

write_watchdog_units() {
  local ch=0
  gen_watchdog_service | sync_file /etc/systemd/system/awg-watchdog.service 644 && ch=1
  gen_watchdog_timer | sync_file /etc/systemd/system/awg-watchdog.timer 644 && ch=1
  if (( ch )); then
    HELPERS_CHANGED=1
    systemctl daemon-reload
    systemctl enable awg-watchdog.timer >/dev/null 2>&1
    systemctl restart awg-watchdog.timer >/dev/null 2>&1
  fi
  return 0
}

setup_watchdog() {
  info "Setting up watchdog (45s) & nightly session rotation..."
  write_watchdog_script
  write_watchdog_units
  systemctl enable --now awg-watchdog.timer >/dev/null 2>&1
  ok "Watchdog (45s) enabled."
  write_rotate_timer "04:30"
}
gen_rotate_script() {
  {
    cat <<'EOF'
#!/usr/bin/env bash
CONF="/etc/amnezia/amneziawg/rotate.conf"
SVC="/etc/systemd/system/udp2raw.service"
META="/etc/amnezia/amneziawg/awg0.meta"

EOF
    declare -f rot_day rot_pick_port
    cat <<'EOF'

conf_get() { sed -n "s/^$1=//p" "$CONF" 2>/dev/null | head -n1; }
POOL=$(conf_get POOL)
SECRET=$(conf_get SECRET)
APPLIED=$(conf_get APPLIED)
TODAY=$(rot_day)

is_foreign() { grep -q ' -s ' "$SVC" 2>/dev/null; }
cur_port() {
  if is_foreign; then
    grep -oE -- '-l 0\.0\.0\.0:[0-9]+' "$SVC" | grep -oE '[0-9]+$'
  else
    grep -oE -- '-r [0-9.]+:[0-9]+' "$SVC" | grep -oE '[0-9]+$'
  fi
}
old_in_use() {
  ss -tlnp 2>/dev/null | awk -v p="$1" 'NR>1 {n=split($4,a,":"); if (a[n]==p) print}' | grep -qv 'udp2raw'
}
ufw_active() { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; }

MODE="${1:-sync}"

if [[ "$MODE" == "--status" ]]; then
  if [[ -n "$POOL" && -n "$SECRET" ]]; then
    echo "Port rotation: ON | pool: ${POOL}"
    echo "Current port: $(cur_port) | next change at 04:30 Tehran -> $(rot_pick_port "$POOL" "$SECRET" 1)"
    [[ "$APPLIED" != "$TODAY" ]] && echo "Pending: port will switch to $(rot_pick_port "$POOL" "$SECRET" 0) at the next sync"
  else
    echo "Port rotation: OFF"
  fi
  exit 0
fi

if [[ -z "$POOL" || -z "$SECRET" ]]; then
  [[ "$MODE" == "--nightly" ]] && systemctl restart udp2raw.service
  exit 0
fi

CUR=$(cur_port)

# Today is already handled; only the nightly run refreshes the session
if [[ "$APPLIED" == "$TODAY" ]]; then
  if [[ "$MODE" == "--nightly" ]]; then
    systemctl restart udp2raw.service
    logger -t awg-port-rotate "Session refreshed on port ${CUR}"
  fi
  exit 0
fi

NEW=$(rot_pick_port "$POOL" "$SECRET" 0) || exit 1

if [[ "$NEW" != "$CUR" ]]; then
  if is_foreign; then
    sed -i -E "s#(-l 0\.0\.0\.0:)[0-9]+#\1${NEW}#" "$SVC"
    ufw_active && ufw allow "${NEW}/tcp" >/dev/null 2>&1
  else
    sed -i -E "s#(-r [0-9.]+:)[0-9]+#\1${NEW}#" "$SVC"
  fi
  [[ -f "$META" ]] && sed -i "s|^RAW_PORT=.*|RAW_PORT=${NEW}|" "$META"
  systemctl daemon-reload
  systemctl restart udp2raw.service
  logger -t awg-port-rotate "FakeTCP port changed ${CUR} -> ${NEW}"
  if is_foreign && ufw_active && ! old_in_use "$CUR"; then
    ufw --force delete allow "${CUR}/tcp" >/dev/null 2>&1
  fi
elif [[ "$MODE" == "--nightly" ]]; then
  systemctl restart udp2raw.service
  logger -t awg-port-rotate "Session refreshed on port ${CUR}"
fi

if grep -q '^APPLIED=' "$CONF"; then
  sed -i "s/^APPLIED=.*/APPLIED=${TODAY}/" "$CONF"
else
  echo "APPLIED=${TODAY}" >> "$CONF"
fi
EOF
  }
}

write_rotate_script() {
  gen_rotate_script | sync_file "$ROT_BIN" 755 && HELPERS_CHANGED=1
  return 0
}

gen_rotate_service() {
  cat <<EOF
[Unit]
Description=Nightly FakeTCP Session / Port Rotation

[Service]
Type=oneshot
ExecStart=${ROT_BIN} --nightly
EOF
}

gen_rotate_timer() {
  cat <<EOF
[Unit]
Description=Rotate FakeTCP Session Daily at ${1} Tehran time

[Timer]
OnCalendar=${2}
AccuracySec=1s
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

# Nightly rotation at Tehran time (UTC+3:30, no daylight saving)
write_rotate_timer() {
  local when="${1:-04:30}" quiet="${2:-}"
  [[ "$when" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "Invalid time. Use HH:MM."
  write_rotate_script
  if [[ -f "$ROT_CONF" ]] && ! grep -q '^APPLIED=' "$ROT_CONF"; then
    echo "APPLIED=$(rot_day)" >> "$ROT_CONF"
  fi
  local cal="*-*-* ${when}:00 Asia/Tehran"

  if ! systemd-analyze calendar "$cal" >/dev/null 2>&1; then
    local h=${when%%:*} m=${when##*:}
    local total=$(( (10#$h * 60 + 10#$m - 210 + 1440) % 1440 ))
    cal=$(printf '*-*-* %02d:%02d:00 UTC' $(( total / 60 )) $(( total % 60 )))
    [[ -n "$quiet" ]] || warn "Timezone suffix unsupported by this systemd. Using UTC equivalent: ${cal}"
  fi

  local ch=0
  gen_rotate_service | sync_file /etc/systemd/system/awg-nightly-rotate.service 644 && ch=1
  gen_rotate_timer "$when" "$cal" | sync_file /etc/systemd/system/awg-nightly-rotate.timer 644 && ch=1

  if (( ch )); then
    HELPERS_CHANGED=1
    systemctl daemon-reload
    systemctl enable awg-nightly-rotate.timer >/dev/null 2>&1
    systemctl restart awg-nightly-rotate.timer >/dev/null 2>&1
  elif [[ -z "$quiet" ]]; then
    systemctl enable --now awg-nightly-rotate.timer >/dev/null 2>&1
  fi
  [[ -n "$quiet" ]] || ok "Nightly rotation set for ${when} Tehran time."
  return 0
}

# ---------- Config file generation ----------
common_iface_block() {
  cat <<EOF
[Interface]
PrivateKey = ${PRIV}
Address = ${SELF_ADDR}/${CIDR}
ListenPort = ${LISTEN_PORT}
MTU = ${MTU}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
S3 = ${S3}
S4 = ${S4}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
EOF
}

write_iran_cfg() {
  local NIC=$1
  mkdir -p "$CFG_DIR"; chmod 700 "$CFG_DIR"

  local DNAT_RULES="" chunk
  if [[ "$FWD_MODE" == "2" ]]; then
    while read -r chunk; do
      [[ -n "$chunk" ]] || continue
      DNAT_RULES+="PostUp = iptables -t nat -A AWG_DNAT -p tcp -m multiport --dports ${chunk} -j DNAT --to-destination ${FR_ADDR}"$'\n'
      DNAT_RULES+="PostUp = iptables -t nat -A AWG_DNAT -p udp -m multiport --dports ${chunk} -j DNAT --to-destination ${FR_ADDR}"$'\n'
    done < <(multiport_chunks "$CUSTOM_PORTS")
  else
    while read -r chunk; do
      [[ -n "$chunk" ]] || continue
      DNAT_RULES+="PostUp = iptables -t nat -A AWG_DNAT -p tcp -m multiport --dports ${chunk} -j RETURN"$'\n'
    done < <(multiport_chunks "${KEEP_TCP_PORTS},25,465,587")
    DNAT_RULES+="PostUp = iptables -t nat -A AWG_DNAT -p tcp -j DNAT --to-destination ${FR_ADDR}"$'\n'
    while read -r chunk; do
      [[ -n "$chunk" ]] || continue
      DNAT_RULES+="PostUp = iptables -t nat -A AWG_DNAT -p udp -m multiport --dports ${chunk} -j RETURN"$'\n'
    done < <(multiport_chunks "${LOCAL_UDP_PORT},${LISTEN_PORT},53")
    DNAT_RULES+="PostUp = iptables -t nat -A AWG_DNAT -p udp -j DNAT --to-destination ${FR_ADDR}"$'\n'
  fi

  local GUARD_RULES="" str
  for str in "youtube.com" "googlevideo.com" "pornhub.com" "BitTorrent protocol"; do
    GUARD_RULES+="PostUp = iptables -A AWG_GUARD -p tcp -m connbytes --connbytes 1:10 --connbytes-mode packets --connbytes-dir original -m string --algo bm --string \"${str}\" -j DROP 2>/dev/null || iptables -A AWG_GUARD -m string --algo bm --string \"${str}\" -j DROP"$'\n'
  done

  { common_iface_block
    cat <<EOF
PostUp = sysctl -qw net.ipv4.ip_forward=1
PostUp = sysctl -qw net.netfilter.nf_conntrack_acct=1 2>/dev/null || true
PostUp = ip link set dev %i txqueuelen 10000 2>/dev/null || true
PostUp = ip link set dev ${NIC} txqueuelen 10000 2>/dev/null || true
PostUp = iptables -t nat -N AWG_DNAT 2>/dev/null || true
PostUp = iptables -t nat -F AWG_DNAT

# Protect the Iran server's own traffic: foreign server, established flows and DNS
PostUp = iptables -t nat -A AWG_DNAT -s ${FOREIGN_IP} -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -d ${FOREIGN_IP} -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -p udp --sport 53 -j RETURN
PostUp = iptables -t nat -A AWG_DNAT -p tcp --sport 53 -j RETURN

# Port forwarding rules
PostUp = iptables -t nat -C PREROUTING -i ${NIC} -j AWG_DNAT 2>/dev/null || iptables -t nat -I PREROUTING 1 -i ${NIC} -j AWG_DNAT
${DNAT_RULES}

# Anti-Bad-SNI & Anti-Abuse (strings are scanned only in the first 10 packets of a connection)
PostUp = iptables -N AWG_GUARD 2>/dev/null || true
PostUp = iptables -F AWG_GUARD
PostUp = iptables -A AWG_GUARD -p tcp -m multiport --dports 25,465,587 -j DROP
PostUp = iptables -A AWG_GUARD ${GUARD_RET} 2>/dev/null || true
${GUARD_RULES}PostUp = iptables -C FORWARD -i ${NIC} -o %i -j AWG_GUARD 2>/dev/null || iptables -I FORWARD 1 -i ${NIC} -o %i -j AWG_GUARD

# NAT & MSS clamping
PostUp = iptables -t nat -C POSTROUTING -o %i -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %i -j MASQUERADE
PostUp = iptables -C FORWARD -i ${NIC} -o %i -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${NIC} -o %i -j ACCEPT
PostUp = iptables -C FORWARD -i %i -o ${NIC} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %i -o ${NIC} -j ACCEPT
PostUp = iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t mangle -C POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

PostDown = iptables -t nat -D PREROUTING -i ${NIC} -j AWG_DNAT 2>/dev/null || true
PostDown = iptables -t nat -F AWG_DNAT 2>/dev/null || true
PostDown = iptables -t nat -X AWG_DNAT 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${NIC} -o %i -j AWG_GUARD 2>/dev/null || true
PostDown = iptables -F AWG_GUARD 2>/dev/null || true
PostDown = iptables -X AWG_GUARD 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${NIC} -o %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i %i -o ${NIC} -j ACCEPT 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = iptables -t mangle -D POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

[Peer]
PublicKey = ${FR_PUB}
PresharedKey = ${PSK}
AllowedIPs = ${FR_ADDR}/32
Endpoint = 127.0.0.1:${LOCAL_UDP_PORT}
PersistentKeepalive = 15
EOF
  } > "$CFG"
  chmod 600 "$CFG"
}

write_foreign_cfg() {
  local NIC=$1
  mkdir -p "$CFG_DIR"; chmod 700 "$CFG_DIR"
  LISTEN_PORT="$AWG_PORT"
  { common_iface_block
    cat <<EOF
PostUp = sysctl -qw net.ipv4.ip_forward=1
PostUp = ip link set dev %i txqueuelen 10000 2>/dev/null || true
PostUp = ip link set dev ${NIC} txqueuelen 10000 2>/dev/null || true
PostUp = iptables -C INPUT -i %i -p tcp --dport ${DETECTED_SSH:-22} -j DROP 2>/dev/null || iptables -I INPUT 1 -i %i -p tcp --dport ${DETECTED_SSH:-22} -j DROP
PostUp = iptables -C INPUT -p udp --dport ${AWG_PORT} ! -i lo -j DROP 2>/dev/null || iptables -I INPUT 1 -p udp --dport ${AWG_PORT} ! -i lo -j DROP
PostUp = iptables -C FORWARD -i %i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %i -j ACCEPT
PostUp = iptables -C FORWARD -o %i -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o %i -j ACCEPT
PostUp = iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o ${NIC} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o ${NIC} -j MASQUERADE
PostUp = iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t mangle -C POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostDown = iptables -D INPUT -i %i -p tcp --dport ${DETECTED_SSH:-22} -j DROP 2>/dev/null || true
PostDown = iptables -D INPUT -p udp --dport ${AWG_PORT} ! -i lo -j DROP 2>/dev/null || true
PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o %i -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o ${NIC} -j MASQUERADE 2>/dev/null || true
PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
PostDown = iptables -t mangle -D POSTROUTING -o %i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
EOF
  } > "$CFG"
  chmod 600 "$CFG"
}

gen_awg_override() {
  cat <<'EOF'
[Service]
EnvironmentFile=-/etc/default/amneziawg
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
EOF
}

write_awg_override() {
  [[ -f /usr/lib/systemd/system/awg-quick@.service || -f /lib/systemd/system/awg-quick@.service ]] || return 0
  mkdir -p "/etc/systemd/system/awg-quick@${IFACE}.service.d"
  if gen_awg_override | sync_file "/etc/systemd/system/awg-quick@${IFACE}.service.d/override.conf" 644; then
    HELPERS_CHANGED=1
    systemctl daemon-reload
  fi
  return 0
}

# On every script start, installed helper files are synced with this script version
auto_refresh_helpers() {
  [[ -f "$SVC" && -f "$META" ]] || return 0
  local role when timer=/etc/systemd/system/awg-nightly-rotate.timer
  role=$(meta_get ROLE)
  [[ "$role" == "iran" || "$role" == "foreign" ]] || return 0
  HELPERS_CHANGED=0

  if gen_sysctl_conf | sync_file /etc/sysctl.d/99-awg-optimizer.conf 644; then
    HELPERS_CHANGED=1
    sysctl -q --system >/dev/null 2>&1 || true
  fi
  gen_limits_conf | sync_file /etc/security/limits.d/99-awg.conf 644 && HELPERS_CHANGED=1
  write_awg_override

  # CPU optimizations: RPS, FakeTCP notrack, lighter Anti-SNI guard
  ensure_rps
  ensure_notrack_in_service
  migrate_guard_rule

  if [[ "$role" == "iran" ]]; then
    write_watchdog_script
    write_watchdog_units
  fi

  if [[ "$role" == "iran" || -f "$ROT_CONF" ]]; then
    when="04:30"
    if grep -q 'Tehran' "$timer" 2>/dev/null; then
      when=$(sed -n 's/.*Daily at \([0-9][0-9]:[0-9][0-9]\).*/\1/p' "$timer" | head -n1)
    fi
    [[ -n "$when" ]] || when="04:30"
    write_rotate_timer "$when" quiet
  fi

  if (( HELPERS_CHANGED )); then
    NOTICE="${GREEN}[+]${RESET} Helper files and CPU optimizations were updated to match this script version."
  fi
  return 0
}

bring_up() {
  set -a; . /etc/default/amneziawg 2>/dev/null || true; set +a
  awg-quick down "$IFACE" >/dev/null 2>&1 || true
  ip link del "$IFACE" >/dev/null 2>&1 || true
  awg-quick up "$IFACE" || die "awg-quick failed to start ${IFACE}."
  if [[ -f /usr/lib/systemd/system/awg-quick@.service || -f /lib/systemd/system/awg-quick@.service ]]; then
    write_awg_override
    systemctl enable "awg-quick@${IFACE}" >/dev/null 2>&1 && ok "AmneziaWG service enabled on boot."
  fi
  ok "Interface ${IFACE} is up (ListenPort: ${LISTEN_PORT})."
}

wait_handshake() {
  local target_peer_ip="${1:-}"
  info "Waiting for handshake over FakeTCP (up to 25s)..."
  for _ in $(seq 1 25); do
    if [[ -n "$target_peer_ip" ]] && ping -c 1 -W 1 "$target_peer_ip" >/dev/null 2>&1; then
      ok "Handshake & ping to ${target_peer_ip} established over FakeTCP."
      return 0
    elif awg show "$IFACE" latest-handshakes 2>/dev/null | awk '{if ($2+0 > 0) found=1} END{exit !found}'; then
      ok "Handshake established over FakeTCP."
      return 0
    fi
    sleep 1
  done
  warn "No handshake yet. Wait 10-15s for keepalive to sync."
  return 1
}

# ---------- Traffic helpers ----------
fmt_bytes() {
  awk -v b="${1:-0}" 'BEGIN {
    split("B KB MB GB TB", u, " "); i = 1
    while (b >= 1024 && i < 5) { b /= 1024; i++ }
    if (i == 1) printf "%d %s", b, u[i]; else printf "%.2f %s", b, u[i]
  }'
}

fmt_dur() {
  local s=${1:-0}
  printf '%dd %02dh %02dm' $(( s / 86400 )) $(( s % 86400 / 3600 )) $(( s % 3600 / 60 ))
}

sys_stat() {
  local v
  v=$(cat "/sys/class/net/$1/statistics/$2" 2>/dev/null)
  [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo 0
}

mbps() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", (b - a) * 8 / 2 / 1000000 }'
}

traffic_section() {
  local role=$1 nic k r t ip label born up_s="" n=0
  local tot_rx=0 tot_tx=0
  local -A peer_ip=()

  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    warn "Tunnel interface ${IFACE} is down; no traffic data."
    return 0
  fi
  nic=$(meta_get NIC); [[ -n "$nic" ]] || nic=$(main_iface)

  born=$(stat -c %Y "/sys/class/net/${IFACE}" 2>/dev/null)
  if [[ "$born" =~ ^[0-9]+$ ]]; then
    up_s=$(( $(date +%s) - born ))
    echo "Counting since tunnel start: $(fmt_dur "$up_s") ago"
  fi
  echo "${DIM}(RX = received by this server, TX = sent by this server; counters reset on tunnel restart)${RESET}"
  echo

  while read -r k ip; do
    [[ -n "$k" ]] && peer_ip[$k]=${ip%%/*}
  done < <(awg show "$IFACE" allowed-ips 2>/dev/null)

  printf '  %-30s %-16s %-16s\n' "Peer" "RX" "TX"
  while read -r k r t; do
    [[ "$r" =~ ^[0-9]+$ && "$t" =~ ^[0-9]+$ ]] || continue
    ip=${peer_ip[$k]:-?}
    if [[ "$role" == "foreign" && "$ip" =~ ^10\.0\.0\.([0-9]+)$ ]]; then
      label="Iran node #$(( BASH_REMATCH[1] - 1 )) (${ip})"
    else
      label="Foreign hub (${ip})"
    fi
    printf '  %-30s %-16s %-16s\n' "$label" "$(fmt_bytes "$r")" "$(fmt_bytes "$t")"
    tot_rx=$(( tot_rx + r )); tot_tx=$(( tot_tx + t )); n=$(( n + 1 ))
  done < <(awg show "$IFACE" transfer 2>/dev/null)

  if (( n == 0 )); then
    echo "  No peers found."
  elif (( n > 1 )); then
    printf '  %-30s %-16s %-16s\n' "TOTAL" "$(fmt_bytes "$tot_rx")" "$(fmt_bytes "$tot_tx")"
  fi
  echo "  Total through tunnel: $(fmt_bytes $(( tot_rx + tot_tx )))"

  echo
  local r1 t1 r2 t2
  r1=$(sys_stat "$IFACE" rx_bytes); t1=$(sys_stat "$IFACE" tx_bytes)
  sleep 2
  r2=$(sys_stat "$IFACE" rx_bytes); t2=$(sys_stat "$IFACE" tx_bytes)
  echo "  Live speed (2s sample): RX $(mbps "$r1" "$r2") Mbps | TX $(mbps "$t1" "$t2") Mbps"

  if [[ -n "$nic" && -d "/sys/class/net/${nic}" ]]; then
    echo "  Main NIC ${nic} since boot: RX $(fmt_bytes "$(sys_stat "$nic" rx_bytes)") | TX $(fmt_bytes "$(sys_stat "$nic" tx_bytes)")"
    echo "  ${DIM}(NIC totals include all traffic, FakeTCP overhead and SSH; compare with the tunnel totals above)${RESET}"
  fi
}

# ============================ Menu actions ============================
action_foreign() {
  if [[ -f "$CFG" ]]; then
    warn "A config already exists. Continuing will regenerate all keys and the token, and every Iran node must be re-added."
    confirm "Continue?" || { info "Cancelled."; return 0; }
  fi

  install_tools; install_udp2raw; setup_backend; sysctl_tuning
  NIC=$(main_iface); [[ -n "$NIC" ]] || die "Cannot detect default network interface."
  FOREIGN_IP=$(pub_ip)
  read -rp "FOREIGN server public IP [${FOREIGN_IP:-none}]: " in_ip
  FOREIGN_IP=${in_ip:-$FOREIGN_IP}
  valid_ipv4 "$FOREIGN_IP" || die "A valid foreign IPv4 address is required."

  RAW_PASS=$(gen_pass)
  ROT_POOL=""
  if confirm_yes "Enable daily web-port rotation at 04:30 Tehran time?"; then
    read -rp "Port pool [${ROT_DEFAULT_POOL}]: " in_pool
    ROT_POOL=$(normalize_pool "${in_pool:-$ROT_DEFAULT_POOL}")
    valid_pool "$ROT_POOL" || die "Pool must contain at least 2 valid ports."
    ROT_POOL=$(filter_free_pool "$ROT_POOL")
    valid_pool "$ROT_POOL" || die "Not enough free ports left in the pool."
    RAW_PORT=$(rot_pick_port "$ROT_POOL" "$RAW_PASS" 0)
    ok "Pool: ${ROT_POOL} | today's FakeTCP port: ${RAW_PORT}"
  else
    SUGGESTED_RAW_PORT=$(rnd_free_port 10000 50000)
    read -rp "FakeTCP listen port [${SUGGESTED_RAW_PORT}]: " RAW_PORT
    RAW_PORT=${RAW_PORT:-$SUGGESTED_RAW_PORT}
    valid_port "$RAW_PORT" || die "Invalid port."
  fi

  AWG_PORT=$(rnd_free_port 25000 55000)
  MTU=1240

  gen_profile
  PRIV=$(awg genkey); FR_PUB=$(echo "$PRIV" | awg pubkey); PSK=$(awg genpsk)
  SELF_ADDR="$FR_ADDR"

  setup_udp2raw_foreign
  write_foreign_cfg "$NIC"
  {
    echo "ROLE=foreign"; echo "NIC=${NIC}"; echo "AWG_PORT=${AWG_PORT}"
    echo "RAW_PORT=${RAW_PORT}"; echo "RAW_PASS=${RAW_PASS}"; echo "MTU=${MTU}"
    echo "PSK=${PSK}"
    echo "TOKEN=$(encode_token)"
  } > "$META"; chmod 600 "$META"
  bring_up
  if [[ -n "$ROT_POOL" ]]; then
    write_rotate_conf "$ROT_POOL" "$RAW_PASS"
    write_rotate_timer "04:30"
  fi

  echo
  ok "Foreign master hub configured (FakeTCP: ${RAW_PORT} | AWG: ${AWG_PORT})."
  echo "${YELLOW}${BOLD}Copy this MASTER TOKEN and paste it on your Iran servers in option 1:${RESET}"
  echo "${CYAN}$(encode_token)${RESET}"
  echo
}

action_iran() {
  if [[ -f "$CFG" ]]; then
    warn "A config already exists on this server."
    confirm "Overwrite it?" || { info "Cancelled."; return 0; }
  fi

  install_tools; install_udp2raw; setup_backend; sysctl_tuning
  NIC=$(main_iface); [[ -n "$NIC" ]] || die "Cannot detect default network interface."
  echo "Paste the MASTER TOKEN from the foreign server:"
  read -rp "> " TOKEN
  decode_token "$TOKEN"
  MTU=1240
  if [[ -n "$ROT_POOL" ]]; then
    RAW_PORT=$(rot_pick_port "$ROT_POOL" "$RAW_PASS" 0)
    info "Daily port rotation enabled. Pool: ${ROT_POOL} | today's FakeTCP port: ${RAW_PORT}"
  fi

  echo ""
  read -rp "Iran node number [1-5]: " NODE_ID
  NODE_ID=${NODE_ID:-1}
  [[ "$NODE_ID" =~ ^[1-5]$ ]] || die "Node number must be between 1 and 5."

  IR_OCTET=$(( NODE_ID + 1 ))
  SELF_ADDR="10.0.0.${IR_OCTET}"

  LOCAL_UDP_PORT=$(rnd_free_port 20000 39999)
  LISTEN_PORT=$(rnd_free_port 40000 59999)

  echo ""
  echo "${CYAN}Port forwarding mode:${RESET}"
  echo "  1 - Forward all ports except excluded ports"
  echo "  2 - Forward only specific ports"
  read -rp "Mode [1]: " FWD_MODE
  FWD_MODE=${FWD_MODE:-1}
  [[ "$FWD_MODE" == "1" || "$FWD_MODE" == "2" ]] || die "Invalid mode."

  CUSTOM_PORTS=""
  if [[ "$FWD_MODE" == "2" ]]; then
    read -rp "Ports to forward, comma-separated, e.g. 2053,2083,8443: " CUSTOM_PORTS
    CUSTOM_PORTS=$(echo "$CUSTOM_PORTS" | tr -d ' ')
    [[ "$CUSTOM_PORTS" =~ ^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*$ ]] || die "Invalid port list."
  else
    warn "Do not forward the login port of your foreign web panel."
    read -rp "TCP ports to exclude [${KEEP_TCP_PORTS}]: " kp
    KEEP_TCP_PORTS=$(echo "${kp:-$KEEP_TCP_PORTS}" | tr -d ' ')
    [[ "$KEEP_TCP_PORTS" =~ ^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*$ ]] || die "Invalid port list."
  fi

  PRIV=$(awg genkey); IR_PUB=$(echo "$PRIV" | awg pubkey)

  setup_udp2raw_iran
  write_iran_cfg "$NIC"
  {
    echo "ROLE=iran"; echo "NODE_ID=${NODE_ID}"; echo "SELF_ADDR=${SELF_ADDR}"
    echo "NIC=${NIC}"; echo "RAW_PORT=${RAW_PORT}"
    echo "LOCAL_UDP_PORT=${LOCAL_UDP_PORT}"; echo "LISTEN_PORT=${LISTEN_PORT}"
    echo "FOREIGN_IP=${FOREIGN_IP}"; echo "MTU=${MTU}"; echo "FWD_MODE=${FWD_MODE}"
  } > "$META"; chmod 600 "$META"
  bring_up
  setup_watchdog
  [[ -n "$ROT_POOL" ]] && write_rotate_conf "$ROT_POOL" "$RAW_PASS"

  echo
  ok "Iran node #${NODE_ID} (${SELF_ADDR}) configured (AWG: ${LISTEN_PORT}, local UDP: ${LOCAL_UDP_PORT})."
  echo "${YELLOW}${BOLD}Copy this node key and paste it on the foreign server in option 4:${RESET}"
  echo "${CYAN}${NODE_ID}:${IR_PUB}${RESET}"
  echo
}

action_add_node() {
  [[ -f "$CFG" ]] || die "No config at ${CFG}. Run option 2 first."
  [[ "$(meta_get ROLE)" == "foreign" ]] || die "This option must be run on the foreign server."

  echo "Enter the Iran node key, e.g. 1:PublicKey"
  read -rp "> " INPUT_KEY
  [[ -n "$INPUT_KEY" ]] || die "Key is required."

  if [[ "$INPUT_KEY" == *:* ]]; then
    NODE_ID="${INPUT_KEY%%:*}"
    IR_PUB="${INPUT_KEY#*:}"
  else
    read -rp "Node number for this key [1-5]: " NODE_ID
    NODE_ID=${NODE_ID:-1}
    IR_PUB="$INPUT_KEY"
  fi
  [[ "$NODE_ID" =~ ^[1-5]$ ]] || die "Node number must be between 1 and 5."
  [[ "$IR_PUB" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "Public key format is invalid."

  PEER_IP="10.0.0.$(( NODE_ID + 1 ))"
  PSK_LINE=$(meta_get PSK)
  [[ -n "$PSK_LINE" ]] || PSK_LINE=$(awk '/^PresharedKey/{print $3; exit}' "$CFG")
  [[ -n "$PSK_LINE" ]] || die "Could not recover PresharedKey."

  cp -a "$CFG" "${CFG}.bak"
  sed -i "/# BEGIN_IRAN_NODE_${NODE_ID}/,/# END_IRAN_NODE_${NODE_ID}/d" "$CFG"

  cat >> "$CFG" <<EOF

# BEGIN_IRAN_NODE_${NODE_ID}
[Peer]
PublicKey = ${IR_PUB}
PresharedKey = ${PSK_LINE}
AllowedIPs = ${PEER_IP}/32
PersistentKeepalive = 15
# END_IRAN_NODE_${NODE_ID}
EOF
  chmod 600 "$CFG"

  apply_awg_live
  ok "Iran node #${NODE_ID} (${PEER_IP}) added/updated. Verifying connection..."
  wait_handshake "$PEER_IP" || true
}

action_health() {
  local role; role=$(meta_get ROLE)
  echo "${CYAN}${BOLD}=== 1. AmneziaWG Interface & Peers ===${RESET}"
  [[ -n "$role" ]] && echo "Role: ${role}"
  awg show "$IFACE" 2>/dev/null || warn "AmneziaWG is not running."
  echo ""
  echo "${CYAN}${BOLD}=== 2. udp2raw FakeTCP ===${RESET}"
  systemctl is-active --quiet udp2raw.service && ok "udp2raw service is ACTIVE." || err "udp2raw service is DOWN."
  echo ""
  echo "${CYAN}${BOLD}=== 3. Watchdog & Nightly Rotation ===${RESET}"
  systemctl is-active --quiet awg-watchdog.timer && ok "Watchdog (45s) is ACTIVE." || warn "Watchdog not active (normal on foreign server)."
  systemctl is-active --quiet awg-nightly-rotate.timer && ok "Nightly rotate is ACTIVE." || warn "Nightly rotate is not active."
  echo ""
  echo "Server time: $(date '+%F %T %Z') | Tehran time: $(TZ=Asia/Tehran date '+%F %T')"
  systemctl list-timers awg-nightly-rotate.timer --no-pager 2>/dev/null | head -n 3
  [[ -x "$ROT_BIN" ]] && "$ROT_BIN" --status
  if [[ "$role" == "foreign" && -f "$ROT_CONF" ]]; then
    local pp p parr
    pp=$(sed -n 's/^POOL=//p' "$ROT_CONF" | head -n1)
    IFS=',' read -ra parr <<< "$pp"
    for p in "${parr[@]}"; do
      port_used_by_other "$p" && warn "Pool port ${p} is used by another service. Remove it from the pool on ALL servers (option 9)."
    done
  fi
  echo ""
  echo "${CYAN}${BOLD}=== 4. Conntrack Usage ===${RESET}"
  CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "N/A")
  CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "N/A")
  echo "Active connections: ${CT_COUNT} / Max: ${CT_MAX}"
  if iptables -t raw -S 2>/dev/null | grep -q 'notrack'; then
    ok "FakeTCP notrack rules are ACTIVE (outer FakeTCP packets skip conntrack)."
  else
    warn "FakeTCP notrack rules are not active."
  fi
  echo ""
  echo "${CYAN}${BOLD}=== 5. Anti-Bad-SNI Guard ===${RESET}"
  iptables -L AWG_GUARD -v -n 2>/dev/null || echo "Guard chain not active on this server."
  echo ""
  echo "${CYAN}${BOLD}=== 6. Tunnel Ping Test ===${RESET}"
  if [[ "$role" == "foreign" ]]; then
    for n in 1 2 3 4 5; do
      nip="10.0.0.$(( n + 1 ))"
      if ping -c 1 -W 1 "$nip" >/dev/null 2>&1; then
        ok "Iran node #${n} (${nip}) is ONLINE."
      else
        warn "Iran node #${n} (${nip}) is offline."
      fi
    done
  else
    ping -c 2 -W 1 "$FR_ADDR" >/dev/null 2>&1 && ok "Foreign hub (${FR_ADDR}) is REACHABLE." || warn "Foreign hub (${FR_ADDR}) not reachable."
  fi
  echo ""
  echo "${CYAN}${BOLD}=== 7. Tunnel Traffic ===${RESET}"
  traffic_section "$role"
}

action_rotate() {
  [[ -f /etc/systemd/system/udp2raw.service ]] || die "udp2raw service not found."
  read -rp "New FakeTCP port (use the same value on foreign and all Iran nodes): " NEW_PORT
  valid_port "$NEW_PORT" || die "Invalid port."
  [[ -f "$ROT_CONF" ]] && warn "Daily port rotation is enabled. This port is replaced at the next 04:30 Tehran."
  OLD_PORT=$(cur_port_from_service)

  if grep -q ' -s ' /etc/systemd/system/udp2raw.service; then
    sed -i -E "s#(-l 0\.0\.0\.0:)[0-9]+#\1${NEW_PORT}#" /etc/systemd/system/udp2raw.service
    if [[ -f "$META" ]]; then
      decode_token "$(meta_get TOKEN)"
      RAW_PORT="$NEW_PORT"
      NEW_TOKEN=$(encode_token)
      sed -i "s|^RAW_PORT=.*|RAW_PORT=${NEW_PORT}|; s|^TOKEN=.*|TOKEN=${NEW_TOKEN}|" "$META"
    fi
    open_ufw_tcp "$NEW_PORT"
  else
    sed -i -E "s#(-r [0-9.]+:)[0-9]+#\1${NEW_PORT}#" /etc/systemd/system/udp2raw.service
    [[ -f "$META" ]] && sed -i "s|^RAW_PORT=.*|RAW_PORT=${NEW_PORT}|" "$META"
  fi

  systemctl daemon-reload
  systemctl restart udp2raw.service
  if grep -q ' -s ' "$SVC" && [[ -n "$OLD_PORT" && "$OLD_PORT" != "$NEW_PORT" ]] && ! port_used_by_other "$OLD_PORT"; then
    close_ufw_tcp "$OLD_PORT"
  fi
  ok "FakeTCP port rotated to ${NEW_PORT} and session refreshed."
}

action_show_token() {
  [[ "$(meta_get ROLE)" == "foreign" ]] || die "This option must be run on the foreign server."
  refresh_meta_token
  local t; t=$(meta_get TOKEN)
  [[ -n "$t" ]] || die "Token not found."
  echo "${YELLOW}${BOLD}MASTER TOKEN (current FakeTCP port: $(meta_get RAW_PORT)):${RESET}"
  echo "${CYAN}${t}${RESET}"
}

action_remove_node() {
  [[ -f "$CFG" ]] || die "No config at ${CFG}."
  [[ "$(meta_get ROLE)" == "foreign" ]] || die "This option must be run on the foreign server."
  read -rp "Iran node number to remove [1-5]: " NODE_ID
  [[ "$NODE_ID" =~ ^[1-5]$ ]] || die "Node number must be between 1 and 5."
  grep -q "# BEGIN_IRAN_NODE_${NODE_ID}" "$CFG" || die "Node #${NODE_ID} is not in the config."
  cp -a "$CFG" "${CFG}.bak"
  sed -i "/# BEGIN_IRAN_NODE_${NODE_ID}/,/# END_IRAN_NODE_${NODE_ID}/d" "$CFG"
  apply_awg_live
  ok "Iran node #${NODE_ID} removed."
}

action_set_rotate() {
  [[ -f "$SVC" ]] || die "udp2raw service not found."
  read -rp "Rotation time in Tehran time, HH:MM [04:30]: " RT
  RT="${RT:-04:30}"
  if [[ -f "$ROT_CONF" && "$RT" < "04:30" ]]; then
    die "With port rotation enabled the time must be 04:30 or later."
  fi
  write_rotate_timer "$RT"
  systemctl list-timers awg-nightly-rotate.timer --no-pager 2>/dev/null | head -n 3
}

action_port_rotation() {
  [[ -f "$SVC" ]] || die "udp2raw service not found. Run the setup first."
  local role="iran"
  grep -q ' -s ' "$SVC" && role="foreign"

  [[ -x "$ROT_BIN" ]] && "$ROT_BIN" --status
  echo
  echo "  1 - Enable / change port pool"
  echo "  2 - Disable"
  echo "  0 - Back"
  read -rp "Choice [0]: " rc

  case "${rc:-0}" in
    1)
      local def pool secret
      def=$(sed -n 's/^POOL=//p' "$ROT_CONF" 2>/dev/null | head -n1)
      def="${def:-$ROT_DEFAULT_POOL}"
      read -rp "Port pool [${def}]: " in_pool
      pool=$(normalize_pool "${in_pool:-$def}")
      valid_pool "$pool" || die "Pool must contain at least 2 valid ports."
      if [[ "$role" == "foreign" ]]; then
        pool=$(filter_free_pool "$pool")
        valid_pool "$pool" || die "Not enough free ports left in the pool."
      fi
      secret=$(svc_secret)
      [[ -n "$secret" ]] || die "Could not read the udp2raw key."
      write_rotate_conf "$pool" "$secret"
      write_rotate_timer "04:30"
      if [[ "$role" == "iran" && -f /usr/local/bin/awg-watchdog.sh ]]; then
        write_watchdog_script
      fi
      [[ "$role" == "foreign" ]] && refresh_meta_token
      ok "Daily port rotation enabled."
      info "Use this exact pool on every server: ${pool}"
      info "The current port does not change now. The first change happens at the next 04:30 Tehran."
      warn "Enable it on the foreign server and ALL Iran nodes before then."
      "$ROT_BIN" --status
      ;;
    2)
      rm -f "$ROT_CONF"
      if [[ "$role" == "foreign" ]]; then
        systemctl disable --now awg-nightly-rotate.timer >/dev/null 2>&1 || true
        refresh_meta_token
      fi
      ok "Port rotation disabled. The current port stays; keep all servers on the same port."
      ;;
    *) return 0 ;;
  esac
}

action_light_guard() {
  [[ "$(meta_get ROLE)" == "iran" ]] || die "This option must be run on an Iran server."
  [[ -f "$CFG" ]] || die "No config at ${CFG}."
  if grep -q 'connbytes' "$CFG"; then
    migrate_guard_rule
    info "Lighter Anti-SNI rules are already applied."
    return 0
  fi
  iptables -m connbytes --help >/dev/null 2>&1 || die "This kernel has no connbytes module."
  warn "The tunnel restarts for a few seconds."
  confirm "Continue?" || { info "Cancelled."; return 0; }

  cp -a "$CFG" "${CFG}.bak"
  sed -i -E 's#^PostUp = iptables -A AWG_GUARD -m string (.*) -j DROP$#PostUp = iptables -A AWG_GUARD -p tcp -m connbytes --connbytes 1:10 --connbytes-mode packets --connbytes-dir original -m string \1 -j DROP 2>/dev/null || iptables -A AWG_GUARD -m string \1 -j DROP#' "$CFG"
  migrate_guard_rule

  grep -q 'nf_conntrack_acct' /etc/sysctl.d/99-awg-optimizer.conf 2>/dev/null \
    || echo "net.netfilter.nf_conntrack_acct = 1" >> /etc/sysctl.d/99-awg-optimizer.conf
  sysctl -qw net.netfilter.nf_conntrack_acct=1 2>/dev/null || true

  LISTEN_PORT=$(meta_get LISTEN_PORT)
  bring_up
  ok "Lighter Anti-SNI rules applied (only the first 10 packets of each connection are scanned)."
}

action_udp2raw_mode() {
  [[ -f "$SVC" ]] || die "udp2raw service not found. Run the setup first."
  local cc ca
  cc=$(grep -oE -- '--cipher-mode [a-z0-9]+' "$SVC" | awk '{print $2}')
  ca=$(grep -oE -- '--auth-mode [a-z0-9]+' "$SVC" | awk '{print $2}')
  echo "Current: cipher=${cc:-?} auth=${ca:-?}"
  echo
  echo "  1 - aes128cbc + hmac_sha1 (default)"
  echo "  2 - xor + simple (lighter on CPU, weaker)"
  echo "  0 - Back"
  read -rp "Choice [0]: " mc

  local nc na
  case "${mc:-0}" in
    1) nc="aes128cbc"; na="hmac_sha1" ;;
    2) nc="xor";       na="simple" ;;
    *) return 0 ;;
  esac

  warn "Cipher and auth mode must be identical on the foreign server and ALL Iran nodes. The tunnel stays down until all of them match."
  confirm "Continue?" || { info "Cancelled."; return 0; }

  sed -i -E "s/--cipher-mode [a-z0-9]+/--cipher-mode ${nc}/; s/--auth-mode [a-z0-9]+/--auth-mode ${na}/" "$SVC"
  systemctl daemon-reload
  systemctl restart udp2raw.service
  ok "udp2raw mode set to ${nc} + ${na}. Repeat on every other server."
}

awg_firewall_pattern() {
  echo "AWG_DNAT|AWG_GUARD|udp2raw|(-i|-o) ${IFACE}( |\$)"
}

action_uninstall() {
  confirm "Remove all tunnel services, rules and configs?" || { info "Cancelled."; return 0; }
  local was_foreign=0 last_port="" pat left=() item rm_bins=0 q
  pat=$(awg_firewall_pattern)

  if confirm "Also remove the installed binaries (udp2raw and amneziawg-go)?"; then
    rm_bins=1
  fi

  grep -q ' -s ' "$SVC" 2>/dev/null && was_foreign=1
  last_port=$(cur_port_from_service)

  info "Stopping timers and services..."
  systemctl disable --now awg-watchdog.timer awg-watchdog.service >/dev/null 2>&1 || true
  systemctl disable --now awg-nightly-rotate.timer awg-nightly-rotate.service >/dev/null 2>&1 || true
  systemctl disable --now "awg-quick@${IFACE}" >/dev/null 2>&1 || true
  systemctl disable --now udp2raw.service >/dev/null 2>&1 || true
  systemctl disable --now awg-rps.service >/dev/null 2>&1 || true

  info "Bringing the tunnel interface down..."
  set -a; . /etc/default/amneziawg 2>/dev/null || true; set +a
  awg-quick down "$IFACE" >/dev/null 2>&1 || true
  ip link del "$IFACE" >/dev/null 2>&1 || true
  pkill -f '/usr/local/bin/udp2raw' >/dev/null 2>&1 || true
  pkill -x amneziawg-go >/dev/null 2>&1 || true
  [[ -x "$NOTRACK_BIN" ]] && "$NOTRACK_BIN" del >/dev/null 2>&1
  sleep 1

  if iptables-save 2>/dev/null | grep -qE "$pat"; then
    info "Removing leftover firewall rules..."
    iptables-save 2>/dev/null | grep -vE "$pat" | iptables-restore 2>/dev/null \
      || warn "Could not clean the firewall automatically."
  fi

  # Revert RPS settings
  for q in /sys/class/net/"$(main_iface)"/queues/rx-*/rps_cpus; do
    [[ -w "$q" ]] && echo 0 > "$q" 2>/dev/null
  done

  rm -rf "$CFG_DIR" /etc/sysctl.d/99-awg-optimizer.conf /etc/modules-load.d/amneziawg.conf \
         /etc/systemd/system/udp2raw.service /etc/systemd/system/awg-watchdog.service \
         /etc/systemd/system/awg-watchdog.timer /usr/local/bin/awg-watchdog.sh \
         /etc/systemd/system/awg-nightly-rotate.service /etc/systemd/system/awg-nightly-rotate.timer \
         /etc/systemd/system/awg-rps.service "$RPS_BIN" "$NOTRACK_BIN" /run/u2r-notrack.rules \
         /etc/security/limits.d/99-awg.conf "/etc/systemd/system/awg-quick@${IFACE}.service.d" "$ROT_BIN"

  if (( rm_bins )); then
    rm -f /usr/local/bin/udp2raw /usr/local/bin/amneziawg-go /etc/default/amneziawg
    ok "Binaries removed (udp2raw, amneziawg-go)."
    info "The amneziawg / amneziawg-tools packages are kept; remove them with apt if you do not need them."
  else
    info "Binaries kept: /usr/local/bin/udp2raw and amneziawg-go (if installed)."
  fi

  systemctl daemon-reload
  if [[ $was_foreign -eq 1 && -n "$last_port" ]] && ! port_used_by_other "$last_port"; then
    close_ufw_tcp "$last_port"
  fi

  ip link show "$IFACE" >/dev/null 2>&1 && left+=("interface ${IFACE} still exists")
  pgrep -f '/usr/local/bin/udp2raw' >/dev/null 2>&1 && left+=("udp2raw is still running")
  pgrep -x amneziawg-go >/dev/null 2>&1 && left+=("amneziawg-go is still running")
  iptables-save 2>/dev/null | grep -qE "$pat" && left+=("tunnel firewall rules are still present")
  iptables -t raw -S 2>/dev/null | grep -q 'notrack' && left+=("notrack rules are still present")

  if (( ${#left[@]} == 0 )); then
    ok "Verified: interface, processes and firewall rules are gone. Services and configs removed."
  else
    for item in "${left[@]}"; do err "$item"; done
    warn "Some parts could not be removed. Reboot this server, or run option 12 again."
  fi
}

hr() {
  echo "${DIM}  ------------------------------------------------------------${RESET}"
}

status_panel() {
  local role label tun u2r port rot pool_n hs now online=0 total=0 last=0 link nt rp
  role=$(meta_get ROLE)
  hr
  if [[ -z "$role" ]]; then
    echo "  Server  : ${YELLOW}not installed${RESET}"
    hr
    return 0
  fi

  if [[ "$role" == "iran" ]]; then
    label="IRAN node #$(meta_get NODE_ID) ($(meta_get SELF_ADDR))"
  else
    label="FOREIGN hub (${FR_ADDR})"
  fi

  if ip link show "$IFACE" >/dev/null 2>&1; then tun="${GREEN}UP${RESET}"; else tun="${RED}DOWN${RESET}"; fi
  if systemctl is-active --quiet udp2raw.service 2>/dev/null; then u2r="${GREEN}active${RESET}"; else u2r="${RED}down${RESET}"; fi
  port=$(cur_port_from_service)

  if [[ -f "$ROT_CONF" ]]; then
    pool_n=$(sed -n 's/^POOL=//p' "$ROT_CONF" | head -n1 | tr ',' '\n' | grep -c .)
    rot="${GREEN}ON${RESET} (${pool_n} ports)"
  else
    rot="${YELLOW}OFF${RESET}"
  fi

  nt="${YELLOW}off${RESET}"; rp="${YELLOW}off${RESET}"
  iptables -t raw -S 2>/dev/null | grep -q 'notrack' && nt="${GREEN}on${RESET}"
  systemctl is-active --quiet awg-rps.service 2>/dev/null && rp="${GREEN}on${RESET}"

  now=$(date +%s)
  if command -v awg >/dev/null 2>&1 && ip link show "$IFACE" >/dev/null 2>&1; then
    while read -r _ hs; do
      [[ "$hs" =~ ^[0-9]+$ ]] || continue
      total=$(( total + 1 ))
      if (( hs > 0 && now - hs < 180 )); then
        online=$(( online + 1 ))
        (( hs > last )) && last=$hs
      fi
    done < <(awg show "$IFACE" latest-handshakes 2>/dev/null)
  fi

  if [[ "$role" == "foreign" ]]; then
    if (( total > 0 && online == total )); then
      link="${GREEN}Iran nodes online ${online}/${total}${RESET}"
    elif (( online == 0 )); then
      link="${RED}Iran nodes online ${online}/${total}${RESET}"
    else
      link="${YELLOW}Iran nodes online ${online}/${total}${RESET}"
    fi
  elif (( online > 0 )); then
    link="${GREEN}hub link OK${RESET} (handshake $(( now - last ))s ago)"
  else
    link="${RED}no recent handshake${RESET}"
  fi

  echo "  Server  : ${BOLD}${label}${RESET}"
  echo "  Tunnel  : ${tun}   udp2raw: ${u2r}   ${link}"
  echo "  FakeTCP : port ${port:-?}   rotation: ${rot}"
  echo "  Perf    : notrack ${nt}   RPS ${rp}"
  echo "  Time    : $(TZ=Asia/Tehran date '+%F %H:%M') Tehran"
  hr
}

menu_section() {
  echo
  echo "  ${CYAN}${BOLD}$1${RESET}"
}

# Items that do not apply to this server's role are dimmed
menu_item() {
  local num=$1 label=$2 scope=${3:-both} pre="" post=""
  if [[ -n "$MENU_ROLE" && "$scope" != "both" && "$scope" != "$MENU_ROLE" ]]; then
    pre="$DIM"; post="$RESET"
  fi
  printf '    %s%-3s %s%s\n' "$pre" "$num" "$label" "$post"
}

show_menu() {
  MENU_ROLE=$(meta_get ROLE)
  menu_section "SETUP"
  menu_item 1  "Iran server setup" iran
  menu_item 2  "Foreign server setup" foreign
  menu_section "MONITOR"
  menu_item 3  "Health check & traffic stats" both
  menu_section "FOREIGN SERVER"
  menu_item 4  "Add / update Iran node key" foreign
  menu_item 5  "Remove Iran node" foreign
  menu_item 6  "Show master token" foreign
  menu_section "IRAN SERVER"
  menu_item 7  "Lighter Anti-SNI rules" iran
  menu_section "BOTH SERVERS"
  menu_item 8  "Change FakeTCP port / refresh session" both
  menu_item 9  "Daily web-port rotation" both
  menu_item 10 "Set nightly rotation time" both
  menu_item 11 "udp2raw cipher mode" both
  menu_section "SYSTEM"
  menu_item 12 "Uninstall" both
  menu_item 0  "Exit" both
  echo
}

# ============================ Main menu loop ============================
auto_refresh_helpers

while true; do
  banner
  status_panel
  if [[ -n "$NOTICE" ]]; then
    echo
    echo "  $NOTICE"
    NOTICE=""
  fi
  show_menu
  read -rp "  Select an option [0-12]: " CHOICE || exit 0

  case "$CHOICE" in
    1)  ( action_iran ) ;;
    2)  ( action_foreign ) ;;
    3)  ( action_health ) ;;
    4)  ( action_add_node ) ;;
    5)  ( action_remove_node ) ;;
    6)  ( action_show_token ) ;;
    7)  ( action_light_guard ) ;;
    8)  ( action_rotate ) ;;
    9)  ( action_port_rotation ) ;;
    10) ( action_set_rotate ) ;;
    11) ( action_udp2raw_mode ) ;;
    12) ( action_uninstall ) ;;
    0|q|Q) echo "Bye."; exit 0 ;;
    "") continue ;;
    *) warn "Invalid choice. Enter a number from 0 to 12." ;;
  esac

  echo
  read -rp "Press Enter to return to the menu..." _ || exit 0
done
