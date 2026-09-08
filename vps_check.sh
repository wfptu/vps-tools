#!/bin/bash

# Oracle VPS 专家级安全巡检脚本 v3.2 (Rootkit 对抗版)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}        Oracle VPS 专家级安全巡检脚本 v3.2          ${NC}"
echo -e "${BLUE}====================================================${NC}"

# --- [0. Rootkit 劫持预检] ---
echo -e "${YELLOW}[0. 系统底层后门检查]${NC}"
if [ -s "/etc/ld.so.preload" ]; then
    echo -e "${RED}警告：发现 /etc/ld.so.preload 被修改！这是 Rootkit 劫持的标志。${NC}"
    read -p "是否尝试强力清除劫持? (y/n): " clear_ld
    if [[ "$clear_ld" == "y" ]]; then
        chattr -ai /etc/ld.so.preload 2>/dev/null
        > /etc/ld.so.preload
        echo -e "${GREEN}劫持已暂时清除。${NC}"
    fi
fi

# --- [1. 顽固定时任务 - 终极物理封锁] ---
echo -e "\n${YELLOW}[1. 顽固定时任务扫描与物理封锁]${NC}"
KEYWORDS="perfcc|perfclean|miner|cryptonight|root/.config|wbin"

# 1. 彻底停止 Cron 并锁定服务
systemctl stop cron 2>/dev/null
systemctl mask cron 2>/dev/null # 彻底禁用，防止它自动启动

# 2. 定位恶意文件并彻底粉碎
CRON_ROOT="/var/spool/cron/crontabs/root"
if grep -qE "$KEYWORDS" "$CRON_ROOT" 2>/dev/null; then
    echo -e "${RED}发现顽固定时任务文件: $CRON_ROOT${NC}"
    read -p "是否执行【物理占位】强力封锁? (y/n): " force_p
    if [[ "$force_p" == "y" ]]; then
        # 解锁父目录和文件
        chattr -ai /var/spool/cron/crontabs/ 2>/dev/null
        chattr -ai "$CRON_ROOT" 2>/dev/null
        
        # 删除原文件
        rm -rf "$CRON_ROOT"
        
        # 【核心奇招】：创建一个名为 root 的【目录】而不是文件
        # 这样木马通过脚本再次写入时，会因为“是一个目录”而报错失败
        mkdir "$CRON_ROOT"
        touch "$CRON_ROOT/.lock"
        chattr +i "$CRON_ROOT"
        echo -e "${GREEN}已执行物理占位：$CRON_ROOT 现在是一个不可写的目录。${NC}"
    fi
fi

# 3. 清理内存中的隐藏监视器
echo -e "${YELLOW}正在清理内存隐藏监视器...${NC}"
ps -ef | grep -vE "grep|sshd|x-ui" | grep -E "/tmp|/var/tmp|/root/.config" | awk '{print $2}' | xargs kill -9 2>/dev/null

# --- [2. 之前的 wbin 残留检查] ---
echo -e "\n${YELLOW}[2. 检查 wbin 目录状态]${NC}"
if [ -d "/usr/bin/wbin" ]; then
    chattr -R -ai /usr/bin/wbin 2>/dev/null
    rm -rf /usr/bin/wbin
    echo -e "${GREEN}已再次清理 wbin。${NC}"
fi

# --- [3. 恢复与重启建议] ---
echo -e "\n${BLUE}====================================================${NC}"
echo -e "${RED}！！！关键操作提示！！！${NC}"
echo -e "${YELLOW}1. 系统已被深度感染，虽然我们执行了物理封锁，但木马可能驻留在内存。${NC}"
echo -e "${YELLOW}2. 请务必立即输入 reboot 重启服务器。${NC}"
echo -e "${YELLOW}3. 重启后，如果需要正常使用定时任务，请联系我恢复 root 权限。${NC}"
echo -e "${BLUE}====================================================${NC}"
systemctl unmask cron 2>/dev/null
