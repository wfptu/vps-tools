#!/usr/bin/env bash
# oracle_vps_guard.sh v5.0
# Oracle VPS health/security toolkit

VERSION="5.0"
REPORT="/root/oracle_vps_guard_$(date +%Y%m%d_%H%M%S).log"
BACKUP="/root/oracle_guard_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP"

GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; NC="\033[0m"

log(){ echo -e "$*" | tee -a "$REPORT"; }
ok(){ log "${GREEN}[OK]${NC} $*"; }
warn(){ log "${YELLOW}[WARN]${NC} $*"; }
high(){ log "${RED}[HIGH]${NC} $*"; }

pkg(){
 command -v apt-get >/dev/null && echo apt && return
 command -v dnf >/dev/null && echo dnf && return
 command -v yum >/dev/null && echo yum && return
 echo none
}

full_check(){
 log "===== SYSTEM ====="
 cat /etc/os-release 2>/dev/null | grep PRETTY_NAME
 uname -a
 uptime
 df -h /

 log "===== PROCESS ====="
 ps aux --sort=-%cpu | head -20

 log "===== CRON ANALYSIS ====="
 for f in /etc/crontab /var/spool/cron/crontabs/root /var/spool/cron/root; do
   [ -f "$f" ] || continue
   log "--- $f ---"
   cat "$f"
   if grep -Ei "curl|wget|base64|/tmp/|/dev/shm/|nc |socat" "$f" >/dev/null; then
      grep -Ei "curl|wget|base64|/tmp/|/dev/shm/|nc |socat" "$f" | grep -Eiv "x-ui|3x-ui|acme.sh|certbot|docker" | while read l; do
          high "Suspicious cron: $l"
      done
   fi
 done

 log "===== SYSTEMD ====="
 grep -RHE "curl|wget|base64|/tmp/|/dev/shm/" /etc/systemd/system 2>/dev/null | head -50

 log "===== SSH ====="
 sshd -T 2>/dev/null | grep -E "port|passwordauthentication|permitrootlogin"

 log "===== NETWORK ====="
 ss -lntup

 log "===== SECURITY ====="
 [ -f /etc/ld.so.preload ] && cat /etc/ld.so.preload
 awk -F: '$3==0{print $1}' /etc/passwd

 log "===== BBR ====="
 sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null
 sysctl net.ipv4.tcp_congestion_control 2>/dev/null

 log "Report: $REPORT"
}

install_tools(){
 case "$(pkg)" in
 apt)
  apt update
  apt install -y curl wget socat chrony htop unzip ca-certificates net-tools fail2ban
 ;;
 dnf|yum)
  $(pkg) install -y curl wget socat chrony htop unzip ca-certificates net-tools fail2ban
 ;;
 esac
}

enable_bbr(){
 modprobe tcp_bbr 2>/dev/null || true
 cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
 sysctl --system
}

enable_chrony(){
 systemctl enable --now chrony 2>/dev/null || systemctl enable --now chronyd 2>/dev/null
}

cleanup_wbin(){
 if [ -e /usr/bin/wbin ]; then
  high "Found /usr/bin/wbin"
  file /usr/bin/wbin
  stat /usr/bin/wbin
  read -rp "Delete? type DELETE: " c
  [ "$c" = DELETE ] && rm -f /usr/bin/wbin
 else
  ok "/usr/bin/wbin not found"
 fi
}

change_port(){
 read -rp "New SSH port: " p
 mkdir -p /etc/ssh/sshd_config.d
 cp /etc/ssh/sshd_config "$BACKUP/" 2>/dev/null || true
 echo "Port $p" >/etc/ssh/sshd_config.d/99-custom-port.conf
 sshd -t && (systemctl restart sshd || systemctl restart ssh)
}

menu(){
 while true; do
 cat <<EOF

Oracle VPS Guard v$VERSION

1. Full security check
2. Install tools + fail2ban
3. Enable Chrony
4. Enable BBR
5. Update system
6. Change root password
7. Change SSH port
8. Cleanup /usr/bin/wbin
9. View latest report
0. Exit
EOF

 read -rp "Select [0-9]: " n
 case $n in
 1) full_check;;
 2) install_tools;;
 3) enable_chrony;;
 4) enable_bbr;;
 5) apt update && apt upgrade -y 2>/dev/null || true;;
 6) passwd root;;
 7) change_port;;
 8) cleanup_wbin;;
 9) less $(ls -t /root/oracle_vps_guard_*.log 2>/dev/null | head -1);;
 0) exit;;
 *) echo invalid;;
 esac
 done
}

[ "$EUID" = 0 ] || { echo "Run as root"; exit 1; }

menu
