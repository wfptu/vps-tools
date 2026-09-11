#!/usr/bin/env bash
# oracle_vps_guard_v5.1
# Bilingual Oracle VPS Security Toolkit

VERSION="5.1"
REPORT="/root/oracle_vps_guard_$(date +%Y%m%d_%H%M%S).log"

log(){ echo -e "$*" | tee -a "$REPORT"; }

audit(){
 log "===== Oracle VPS Audit / 安全巡检 ====="
 cat /etc/os-release 2>/dev/null | grep PRETTY_NAME
 uname -a
 uptime
 df -h /
 ps aux --sort=-%cpu | head -20

 log "===== Cron / 定时任务 ====="
 for f in /etc/crontab /var/spool/cron/crontabs/root /var/spool/cron/root; do
  [ -f "$f" ] || continue
  cat "$f"
  grep -Ei "curl|wget|base64|/tmp/|/dev/shm/|nc |socat" "$f" 2>/dev/null |
  grep -Eiv "x-ui|3x-ui|acme.sh|certbot|docker" &&
  log "[HIGH] Suspicious cron / 可疑任务"
 done

 log "===== SSH / 网络 ====="
 sshd -T 2>/dev/null | grep port
 ss -lntup

 [ -e /usr/bin/wbin ] && log "[HIGH] IOC /usr/bin/wbin"

 log "Report: $REPORT"
}

ssh_port(){
 read -rp "New SSH port / 新SSH端口: " p
 mkdir -p /etc/ssh/sshd_config.d
 cp /etc/ssh/sshd_config /root/sshd_config.backup 2>/dev/null || true

 sed -ri 's/^Port /#OldPort /' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true

 echo "Port $p" >/etc/ssh/sshd_config.d/99-custom-port.conf

 if sshd -t; then
  systemctl restart sshd 2>/dev/null || systemctl restart ssh
  echo "New port configured / 新端口已配置: $p"
  echo "Test new SSH before logout / 退出前测试新连接"
 else
  echo "SSH config error / SSH配置错误"
 fi
}

disable22(){
 echo "WARNING: Closing port 22 may lock you out."
 read -rp "Type YES to continue: " c
 [ "$c" = YES ] || return

 mkdir -p /etc/ssh/sshd_config.d
 echo "# Port 22 disabled after migration" >/etc/ssh/sshd_config.d/100-disable22.conf

 systemctl restart sshd 2>/dev/null || systemctl restart ssh

 echo "Remove TCP22 from OCI Security List/NSG too."
}

dd_backup(){
 mkdir -p /root/oracle_guard_backup
 tar czf /root/oracle_guard_backup/config_backup.tar.gz  /etc/ssh /etc/x-ui /usr/local/x-ui /root 2>/dev/null || true
 crontab -l >/root/oracle_guard_backup/root_cron.txt 2>/dev/null || true
 ip addr >/root/oracle_guard_backup/network.txt
 echo "Backup completed / 备份完成"
}

install_tools(){
 apt update 2>/dev/null || true
 apt install -y curl wget socat chrony htop unzip ca-certificates net-tools fail2ban 2>/dev/null || true
 dnf install -y curl wget socat chrony htop unzip ca-certificates net-tools fail2ban 2>/dev/null || true
}

secure_mode(){
 echo "Risk: SSH changes may disconnect you."
 read -rp "Continue YES: " c
 [ "$c" = YES ] || return

 mkdir -p /etc/ssh/sshd_config.d
 cat >/etc/ssh/sshd_config.d/98-hardening.conf <<EOF
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 5
EOF

 systemctl restart sshd 2>/dev/null || systemctl restart ssh
}

menu(){
while true; do
cat <<EOF

Oracle VPS Guard v$VERSION

1 Audit / 巡检
2 Secure mode / 安全基线
3 Change SSH port / 修改SSH端口
4 Disable SSH 22 / 关闭22端口
5 Install tools+Fail2ban / 安装工具
6 DD backup / 重装备份
0 Exit / 退出

EOF

read -rp "Select / 选择: " n
case $n in
1)audit;;
2)secure_mode;;
3)ssh_port;;
4)disable22;;
5)install_tools;;
6)dd_backup;;
0)exit;;
*)echo Invalid;;
esac
done
}

[ "$EUID" = 0 ] || exit 1
menu
