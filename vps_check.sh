#!/usr/bin/env bash
# Oracle VPS Health Check & Security Toolkit v4.0
# Supports: Debian / Ubuntu / Oracle Linux / RHEL-like systems
# Design: risk analysis first; no automatic deletion of merely "suspicious" files.
# IMPORTANT: OCI Security List / NSG rules must also allow the new SSH port.

set -u
umask 077

VERSION="4.1"
BACKUP_DIR="/root/vps_security_backup_$(date +%Y%m%d_%H%M%S)"
REPORT="/root/vps_health_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log(){ echo -e "$*" | tee -a "$REPORT"; }
ok(){ log "${GREEN}[OK]${NC} $*"; }
warn(){ log "${YELLOW}[WARN]${NC} $*"; }
bad(){ log "${RED}[HIGH]${NC} $*"; }
info(){ log "${BLUE}[INFO]${NC} $*"; }

require_root() {
  [[ $EUID -eq 0 ]] || { echo "请使用 root 或 sudo 执行。"; exit 1; }
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] && cp -a "$f" "$BACKUP_DIR/" 2>/dev/null || true
}

pkg_manager() {
  command -v apt-get >/dev/null 2>&1 && echo apt
  command -v dnf >/dev/null 2>&1 && echo dnf
  command -v yum >/dev/null 2>&1 && echo yum
}

service_name_sshd() {
  systemctl list-unit-files 2>/dev/null | awk '$1=="ssh.service"{print "ssh"; exit}
                                      $1=="sshd.service"{print "sshd"; exit}'
}

# ---------- Health check ----------

check_system() {
  log "\n${BLUE}=== 1. 系统基本状态 ===${NC}"
  uname -a
  cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)=' || true
  log "Uptime: $(uptime -p 2>/dev/null || uptime)"
  log "Disk:"
  df -h / | tail -1
  log "Memory:"
  free -h 2>/dev/null || true
}

check_cpu_processes() {
  log "\n${BLUE}=== 2. CPU / 异常进程 ===${NC}"
  ps -eo user,pid,ppid,%cpu,%mem,lstart,cmd --sort=-%cpu | head -16 | tee -a "$REPORT"

  local suspicious=0
  while read -r pid exe; do
    [[ -z "$pid" || -z "$exe" ]] && continue
    if [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm)/ ]] ||
       [[ "$exe" =~ \(deleted\)$ ]]; then
      bad "高风险运行文件: PID=$pid EXE=$exe"
      suspicious=1
    fi
  done < <(for p in /proc/[0-9]*; do
             pid=${p##*/}
             exe=$(readlink "$p/exe" 2>/dev/null || true)
             echo "$pid $exe"
           done)
  ((suspicious==0)) && ok "未发现明显的 /tmp、/var/tmp、/dev/shm 执行文件"
}

check_cron() {
  log "\n${BLUE}=== 3. Cron / 定时持久化智能分析 ===${NC}"

  local files=(
    "/var/spool/cron/crontabs/root"
    "/var/spool/cron/root"
    "/etc/crontab"
  )

  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    log "--- $f ---"
    cat "$f" 2>/dev/null | tee -a "$REPORT"

    local high=0
    # 高风险行为：下载后直接解释执行、隐藏临时目录执行、反弹 shell、明显混淆
    if grep -Eiq 'curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|'
'curl.*https?://.*(-s|--silent).*bash|wget.*https?://.*-O[[:space:]]*-[[:space:]]*\||'
'/tmp/[^[:space:]]+|/var/tmp/[^[:space:]]+|/dev/shm/[^[:space:]]+|'
'nc[[:space:]].*(-e|-c)|socat.*exec|base64[[:space:]].*(-d|--decode).*sh|'
'python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e' "$f" 2>/dev/null; then
      high=1
    fi

    # 常见正常任务白名单：x-ui/3x-ui、acme.sh、certbot、docker 等。
    if ((high==1)); then
      # 若整行只涉及常见管理软件，不直接判高危
      local high_lines
      high_lines=$(grep -Eiv 'x-ui|3x-ui|acme\.sh|certbot|docker|logrotate|anacron|updatedb|fstrim' "$f" 2>/dev/null |
                   grep -Ei 'curl|wget|/tmp/|/var/tmp/|/dev/shm/|base64|python.*-c|perl.*-e|nc .* -e|socat.*exec' || true)
      if [[ -n "$high_lines" ]]; then
        bad "发现高风险 Cron 行，请人工确认:"
        echo "$high_lines" | tee -a "$REPORT"
      else
        ok "命中下载/执行特征，但属于已知管理任务白名单，跳过误报"
      fi
    else
      ok "未发现明显恶意 Cron 特征"
    fi
  done

  # cron.d / periodic jobs
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' f; do
      if grep -Eiq 'curl.*\||wget.*\||/dev/shm/|/tmp/|base64.*-d|python.*-c|nc .* -e|socat.*exec' "$f" 2>/dev/null; then
        bad "高风险定时任务: $f"
      fi
    done < <(find "$d" -type f -maxdepth 2 -print0 2>/dev/null)
  done
}

check_systemd() {
  log "\n${BLUE}=== 4. Systemd 持久化检查 ===${NC}"
  local dirs=(/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system)
  local found=0
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' f; do
      if grep -Eiq '(/tmp/|/var/tmp/|/dev/shm/|curl.*\||wget.*\||base64.*-d|nc .* -e|socat.*exec)' "$f" 2>/dev/null; then
        bad "高风险 systemd 单元: $f"
        grep -Ei 'ExecStart|ExecStartPre|ExecStartPost' "$f" 2>/dev/null | tee -a "$REPORT"
        found=1
      fi
    done < <(find "$d" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) -print0 2>/dev/null)
  done
  ((found==0)) && ok "未发现明显恶意 systemd 持久化特征"
}

check_preload() {
  log "\n${BLUE}=== 5. LD_PRELOAD 检查 ===${NC}"
  if [[ -f /etc/ld.so.preload ]]; then
    local content
    content=$(grep -v '^[[:space:]]*#' /etc/ld.so.preload 2>/dev/null | sed '/^[[:space:]]*$/d' || true)
    if [[ -n "$content" ]]; then
      bad "/etc/ld.so.preload 非空："
      echo "$content" | tee -a "$REPORT"
    else
      ok "/etc/ld.so.preload 为空"
    fi
  else
    ok "不存在 /etc/ld.so.preload"
  fi
}

check_ssh_keys() {
  log "\n${BLUE}=== 6. SSH 授权密钥检查 ===${NC}"
  local found=0
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ -d "$home/.ssh" ]] || continue
    [[ -f "$home/.ssh/authorized_keys" ]] || continue
    log "--- $user : $home/.ssh/authorized_keys ---"
    awk '{print NR ": " $1 " " $2 " " $3}' "$home/.ssh/authorized_keys" 2>/dev/null | tee -a "$REPORT"
    found=1
  done < /etc/passwd
  ((found==0)) && ok "未发现 authorized_keys"
  warn "密钥是否恶意必须结合你的实际登录设备人工确认，脚本不会自动删除。"
}

check_network() {
  log "\n${BLUE}=== 7. 网络监听与异常连接 ===${NC}"
  if command -v ss >/dev/null 2>&1; then
    log "-- Listening --"
    ss -lntup 2>/dev/null | tee -a "$REPORT"
    log "-- Established --"
    ss -ntp state established 2>/dev/null | head -50 | tee -a "$REPORT"
  fi
}

check_suid() {
  log "\n${BLUE}=== 8. SUID/SGID 异常检查 ===${NC}"
  find /usr/bin /usr/sbin /bin /sbin -xdev -type f \( -perm -4000 -o -perm -2000 \) \
    -printf '%M %u %g %p\n' 2>/dev/null | sort | tee -a "$REPORT"
  ok "仅列出结果，不因 SUID 本身判定病毒；请关注陌生路径和近期新增文件。"
}

check_recent_exec() {
  log "\n${BLUE}=== 9. 最近修改的可执行文件 ===${NC}"
  find /tmp /var/tmp /dev/shm /usr/local/bin /usr/local/sbin /opt -xdev -type f \
    -mtime -7 -executable -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null \
    | sort -r | head -100 | tee -a "$REPORT"
}

check_logs() {
  log "\n${BLUE}=== 10. SSH 登录异常 ===${NC}"
  if command -v journalctl >/dev/null 2>&1; then
    journalctl --since "7 days ago" -u ssh -u sshd --no-pager 2>/dev/null |
      grep -Ei 'Failed|Accepted|Invalid|authentication failure|BREAK-IN' |
      tail -100 | tee -a "$REPORT" || true
  fi
  if [[ -f /var/log/auth.log ]]; then
    grep -Ei 'Failed password|Accepted password|Accepted publickey|Invalid user' \
      /var/log/auth.log 2>/dev/null | tail -100 | tee -a "$REPORT"
  elif [[ -f /var/log/secure ]]; then
    grep -Ei 'Failed password|Accepted password|Accepted publickey|Invalid user' \
      /var/log/secure 2>/dev/null | tail -100 | tee -a "$REPORT"
  fi
}

run_health_check() {
  check_system
  check_cpu_processes
  check_cron
  check_systemd
  check_preload
  check_ssh_keys
  check_network
  check_suid
  check_recent_exec
  check_logs
  check_bbr_chrony
  log "\n${GREEN}巡检完成。报告：$REPORT${NC}"
  log "备份目录：$BACKUP_DIR"
}


# ---------- Oracle baseline / performance operations ----------

install_base_tools() {
  log "\n${BLUE}=== 安装常用基础工具 ===${NC}"
  local pm
  pm=$(pkg_manager)

  case "$pm" in
    apt)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl wget socat chrony htop unzip net-tools ca-certificates
      ;;
    dnf)
      dnf install -y curl wget socat chrony htop unzip net-tools ca-certificates
      ;;
    yum)
      yum install -y curl wget socat chrony htop unzip net-tools ca-certificates
      ;;
    *)
      bad "无法识别包管理器"; return 1 ;;
  esac

  ok "基础工具安装完成"
}

configure_chrony() {
  log "\n${BLUE}=== Chrony 时间同步 ===${NC}"
  local service=""
  if systemctl list-unit-files 2>/dev/null | grep -q '^chronyd\.service'; then
    service="chronyd"
  elif systemctl list-unit-files 2>/dev/null | grep -q '^chrony\.service'; then
    service="chrony"
  fi

  if [[ -z "$service" ]]; then
    install_base_tools || return 1
    if systemctl list-unit-files 2>/dev/null | grep -q '^chronyd\.service'; then
      service="chronyd"
    else
      service="chrony"
    fi
  fi

  systemctl enable --now "$service" 2>/dev/null || {
    bad "无法启动 $service"
    return 1
  }

  if command -v chronyc >/dev/null 2>&1; then
    chronyc tracking 2>/dev/null | tee -a "$REPORT" || true
    chronyc sources -v 2>/dev/null | head -20 | tee -a "$REPORT" || true
  fi
  ok "Chrony 已启用并启动"
}

configure_bbr() {
  log "\n${BLUE}=== BBR 网络拥塞控制 ===${NC}"

  local available current
  available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
  current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)

  info "可用拥塞控制：${available:-未知}"
  info "当前拥塞控制：${current:-未知}"

  # 新版 Debian/Oracle Linux 的 BBR 通常已经由内核提供。
  # 不强制替换内核；仅在模块存在时尝试加载。
  if ! grep -qw bbr <<<"$available"; then
    modprobe tcp_bbr 2>/dev/null || true
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
  fi

  if ! grep -qw bbr <<<"$available"; then
    warn "当前内核未提供 BBR，跳过配置，不强行安装/替换内核。"
    return 0
  fi

  mkdir -p /etc/modules-load.d /etc/sysctl.d

  if modinfo tcp_bbr >/dev/null 2>&1; then
    cat > /etc/modules-load.d/bbr.conf <<'EOF'
tcp_bbr
EOF
  fi

  cat > /etc/sysctl.d/99-bbr.conf <<'EOF'
# Managed by vps_check.sh
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

  sysctl --system >/dev/null 2>&1 || true

  current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
  if [[ "$current" == "bbr" ]]; then
    ok "BBR 已启用：$current"
  else
    warn "BBR 配置文件已写入，但当前状态为：${current:-未知}"
  fi
}

system_baseline() {
  log "\n${BLUE}=== Oracle VPS 基础环境初始化 ===${NC}"
  install_base_tools || return 1
  configure_chrony || true
  configure_bbr || true
  system_update
  log "\n${GREEN}基础初始化完成。建议重新运行「完整健康巡检」。${NC}"
}

check_bbr_chrony() {
  log "\n${BLUE}=== 11. BBR / 时间同步状态 ===${NC}"
  local cc
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
  local avail
  avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
  log "BBR available: ${avail:-unknown}"
  log "Current congestion control: ${cc:-unknown}"
  if [[ "$cc" == "bbr" ]]; then
    ok "BBR 当前生效"
  else
    warn "BBR 当前未生效（不一定是问题，取决于内核/用途）"
  fi

  if command -v chronyc >/dev/null 2>&1; then
    chronyc tracking 2>/dev/null | tee -a "$REPORT" || true
  else
    warn "未安装 chronyc"
  fi
}

# ---------- Security operations ----------

change_password() {
  log "\n${BLUE}=== 修改 root 密码 ===${NC}"
  passwd root
}

get_sshd_config() {
  local s
  s=$(service_name_sshd)
  [[ -n "$s" ]] && echo "$s" || echo ssh
}

current_ssh_port() {
  local p
  p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}' || true)
  [[ -n "$p" ]] && echo "$p" || echo 22
}

change_ssh_port() {
  local service newport oldport cfg dropin
  service=$(get_sshd_config)
  oldport=$(current_ssh_port)

  read -rp "当前 SSH 端口 [$oldport]，输入新端口（1024-65535）: " newport
  [[ "$newport" =~ ^[0-9]+$ ]] || { echo "端口格式错误"; return 1; }
  ((newport>=1024 && newport<=65535)) || { echo "建议使用 1024-65535"; return 1; }
  [[ "$newport" != "$oldport" ]] || { echo "与当前端口相同"; return 0; }

  cfg="/etc/ssh/sshd_config"
  dropin="/etc/ssh/sshd_config.d/99-vps-security.conf"
  mkdir -p /etc/ssh/sshd_config.d
  backup_file "$cfg"
  backup_file "$dropin"

  # 不删除原配置，使用独立 drop-in 覆盖。
  cat > "$dropin" <<EOF
# Managed by vps_check.sh
Port $newport
EOF

  if ! sshd -t 2>/dev/null; then
    bad "sshd 配置测试失败，正在恢复。"
    rm -f "$dropin"
    return 1
  fi

  info "即将重启 SSH。请务必先在 OCI Security List/NSG 放行 TCP $newport。"
  read -rp "已确认 OCI 网络规则已放行 $newport，继续？(y/N): " yn
  [[ "$yn" =~ ^[Yy]$ ]] || { rm -f "$dropin"; echo "已取消"; return 0; }

  systemctl restart "$service"
  sleep 2

  local actual
  actual=$(current_ssh_port)
  if [[ "$actual" == "$newport" ]]; then
    ok "SSH 已切换到 $newport。当前会话不要关闭，先用新端口建立第二个 SSH 会话测试。"
  else
    bad "未确认 SSH 已切换，请不要退出当前会话。"
    return 1
  fi
}

harden_ssh() {
  local service cfg dropin
  service=$(get_sshd_config)
  cfg="/etc/ssh/sshd_config"
  dropin="/etc/ssh/sshd_config.d/98-vps-hardening.conf"

  mkdir -p /etc/ssh/sshd_config.d
  backup_file "$cfg"
  backup_file "$dropin"

  cat > "$dropin" <<'EOF'
# Managed by vps_check.sh
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 4
X11Forwarding no
EOF

  if sshd -t 2>/dev/null; then
    systemctl restart "$service"
    ok "SSH 已启用基础加固：密钥登录、禁密码、限制认证次数。"
    warn "执行前必须确认你已有可用 SSH 公钥；否则可能把自己锁在服务器外。"
  else
    rm -f "$dropin"
    bad "sshd 配置测试失败，未应用。"
  fi
}

install_fail2ban() {
  local pm
  pm=$(pkg_manager)
  case "$pm" in
    apt)
      apt-get update && apt-get install -y fail2ban
      ;;
    dnf)
      dnf install -y epel-release 2>/dev/null || true
      dnf install -y fail2ban
      ;;
    yum)
      yum install -y epel-release 2>/dev/null || true
      yum install -y fail2ban
      ;;
    *)
      bad "未识别包管理器"; return 1;;
  esac
  systemctl enable --now fail2ban 2>/dev/null || true
  ok "Fail2ban 已安装/启动（若发行版仓库提供）。"
}

system_update() {
  local pm
  pm=$(pkg_manager)
  case "$pm" in
    apt) apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y ;;
    dnf) dnf upgrade -y ;;
    yum) yum update -y ;;
    *) bad "无法识别包管理器"; return 1;;
  esac
}

show_firewall() {
  log "\n${BLUE}=== 防火墙状态 ===${NC}"
  if command -v ufw >/dev/null 2>&1; then
    ufw status verbose 2>/dev/null || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --state 2>/dev/null || true
    firewall-cmd --list-all 2>/dev/null || true
  fi
  if command -v nft >/dev/null 2>&1; then
    nft list ruleset 2>/dev/null | head -200 | tee -a "$REPORT"
  fi
}

safe_cleanup() {
  log "\n${BLUE}=== 高风险项人工确认清理 ===${NC}"
  warn "本功能只清理由本脚本明确发现的高风险路径；不会删除 x-ui、acme.sh 等正常软件。"
  warn "建议先运行完整巡检并阅读报告。"

  local target
  read -rp "输入要清理的【绝对路径】（例如 /tmp/xxx），或输入 q 退出: " target
  [[ "$target" == "q" ]] && return 0
  [[ "$target" == /* ]] || { echo "必须是绝对路径"; return 1; }
  [[ "$target" != "/" && "$target" != "/usr" && "$target" != "/etc" && "$target" != "/var" && "$target" != "/root" ]] ||
    { bad "拒绝删除系统关键目录"; return 1; }

  if [[ -e "$target" ]]; then
    ls -lad "$target"
    file "$target" 2>/dev/null || true
    read -rp "确认删除 $target ? 输入 DELETE: " confirm
    [[ "$confirm" == "DELETE" ]] || { echo "已取消"; return 0; }
    chattr -i -a "$target" 2>/dev/null || true
    rm -rf --one-file-system -- "$target"
    ok "已删除：$target"
  else
    echo "目标不存在。"
  fi
}

menu() {
  while true; do
    echo
    echo "=============================================="
    echo " Oracle VPS Health & Security Toolkit v$VERSION"
    echo "=============================================="
    echo " 1. 完整健康巡检"
    echo " 2. 查看防火墙"
    echo " 3. 修改 root 密码"
    echo " 4. 修改 SSH 端口"
    echo " 5. SSH 安全加固（密钥登录/禁密码）"
    echo " 6. 安装/启用 Fail2ban"
    echo " 7. 系统更新"
    echo " 8. 人工确认后清理高风险文件"
    echo " 9. 查看最近一次报告"
    echo "10. Oracle VPS 基础初始化（工具/Chrony/BBR/更新)"
    echo " 0. 退出"
    echo "----------------------------------------------"
    read -rp "请选择 [0-9]: " choice
    case "$choice" in
      1) run_health_check ;;
      2) show_firewall ;;
      3) change_password ;;
      4) change_ssh_port ;;
      5) harden_ssh ;;
      6) install_fail2ban ;;
      7) system_update ;;
      8) safe_cleanup ;;
      9) ls -1t /root/vps_health_*.log 2>/dev/null | head -1 | xargs -r less ;;
      0) exit 0 ;;
      *) echo "无效选项" ;;
    esac
  done
}

require_root
menu
