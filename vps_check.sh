#!/bin/bash

# Oracle VPS 专家级安全巡检脚本 v3.1 (顽固木马针对版)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}        Oracle VPS 专家级安全巡检脚本 v3.1          ${NC}"
echo -e "${BLUE}====================================================${NC}"

# --- [1. Swap 检查] ---
echo -e "\n${YELLOW}[1. 虚拟内存 (Swap) 检查]${NC}"
SWAP_TOTAL=$(free -m | awk '/Swap:/ { print $2 }')
if [ "$SWAP_TOTAL" -eq 0 ]; then
    read -p "是否创建 2GB Swap? (y/n): " swp_c
    [[ "$swp_c" == "y" ]] && fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# --- [2. 顽固恶意定时任务清理 - 核心改进] ---
echo -e "\n${YELLOW}[2. 恶意定时任务扫描 (深度清理模式)]${NC}"
KEYWORDS="perfcc|perfclean|miner|cryptonight|root/.config|wbin"

# A. 先停止 cron 服务，断掉木马的监控
systemctl stop cron 2>/dev/null
systemctl stop crond 2>/dev/null

# B. 扫描包含关键字的文件
SUS_FILES=$(grep -rlE "$KEYWORDS" /etc/cron* /var/spool/cron/crontabs /etc/crontab 2>/dev/null)

if [ -z "$SUS_FILES" ]; then
    echo -e "${GREEN}未发现明显的恶意定时任务。${NC}"
else
    for f in $SUS_FILES; do
        echo -e "--------------------------------------"
        echo -e "发现可疑文件: ${RED}$f${NC}"
        read -p "是否执行【外科手术式】清理? (y/n): " cfm
        if [[ "$cfm" == "y" ]]; then
            # 1. 解锁文件本身
            chattr -ai "$f" 2>/dev/null
            # 2. 关键：解锁父目录（防止目录锁定导致删除失败）
            PARENT_DIR=$(dirname "$f")
            chattr -ai "$PARENT_DIR" 2>/dev/null
            
            if [[ "$f" == *"crontabs/root" || "$f" == *"/etc/crontab" ]]; then
                # 使用 sed 强力删除并强制同步到磁盘
                sed -i "/$KEYWORDS/d" "$f" && sync
                echo -e "${GREEN}恶意行已抹除。${NC}"
            else
                rm -f "$f" && sync
                echo -e "${GREEN}文件已彻底删除。${NC}"
            fi
        fi
    done
fi

# C. 物理占位：防止木马再次创建可疑文件
if [ ! -d "/root/.config/cron" ]; then
    echo -e "${YELLOW}执行路径物理封锁...${NC}"
    mkdir -p /root/.config 2>/dev/null
    rm -rf /root/.config/cron 2>/dev/null
    touch /root/.config/cron
    chattr +i /root/.config/cron
    echo -e "${GREEN}已封锁路径: /root/.config/cron (木马将无法在此创建文件)${NC}"
fi

# D. 重启服务
systemctl start cron 2>/dev/null
systemctl start crond 2>/dev/null

# --- [3. 顽固挂载点清理 (保留 v3.0 逻辑)] ---
echo -e "\n${YELLOW}[3. 顽固挂载点检查]${NC}"
WBIN_PATH="/usr/bin/wbin"
if [ -d "$WBIN_PATH" ] || grep -q "$WBIN_PATH" /proc/mounts; then
    echo -e "${RED}检测到 wbin 挂载残留！${NC}"
    read -p "是否执行暴力卸载? (y/n): " dwbin
    if [[ "$dwbin" == "y" ]]; then
        grep "$WBIN_PATH" /proc/mounts | awk '{print $2}' | sort -r | while read -r mnt; do umount -f -l "$mnt" 2>/dev/null; done
        chattr -R -ai "$WBIN_PATH" 2>/dev/null
        rm -rf "$WBIN_PATH"
    fi
fi

# --- [4. 系统变动与服务检查] ---
echo -e "\n${YELLOW}[4. 异常进程扫描]${NC}"
# 寻找没有 TTY 且 CPU 异常的进程
SUS_PROC=$(ps -eo pid,pcpu,args --sort=-pcpu | grep -vE "grep|x-ui|sshd|systemd" | head -n 5)
echo -e "当前高 CPU 进程预览:\n$SUS_PROC"

# --- [5. SSH 加固] ---
echo -e "\n${YELLOW}[5. SSH 访问安全]${NC}"
AK="/root/.ssh/authorized_keys"
if [ -f "$AK" ]; then
    read -p "是否检查并清空 SSH 公钥? (y/n): " c_ak
    [[ "$c_ak" == "y" ]] && > "$AK" && echo -e "${GREEN}已清空。${NC}"
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}巡检结束，建议立即 reboot 重启系统以彻底清除内存残留！${NC}"
echo -e "${BLUE}====================================================${NC}"
