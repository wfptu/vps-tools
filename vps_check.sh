#!/bin/bash

# Oracle VPS 专家级安全巡检脚本 v3.3 (终极对抗版)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}       Oracle VPS 终极对抗巡检脚本 v3.3             ${NC}"
echo -e "${BLUE}====================================================${NC}"

# --- [0. 劫持诊断 (关键)] ---
echo -e "${YELLOW}[0. 检查系统命令是否被劫持]${NC}"
lsattr_check=$(lsattr -V 2>&1 | grep "e2fsprogs")
if [ -z "$lsattr_check" ]; then
    echo -e "${RED}警告：lsattr 命令可能被替换，返回信息不可信！${NC}"
fi

# --- [1. 针对 perfcc 的外科手术式打击] ---
echo -e "\n${YELLOW}[1. 顽固定时任务 - 终极物理切断]${NC}"
CRON_DIR="/var/spool/cron/crontabs"
CRON_FILE="$CRON_DIR/root"

if [ -f "$CRON_FILE" ]; then
    echo -e "${RED}检测到顽固文件: $CRON_FILE${NC}"
    read -p "是否尝试【目录级重命名】来断开木马连接? (y/n): " force_nuke
    if [[ "$force_nuke" == "y" ]]; then
        # 1. 停止所有相关服务
        systemctl stop cron crond 2>/dev/null
        
        # 2. 解锁并重命名整个目录（让木马找不到路径）
        chattr -aiR /var/spool/cron/ 2>/dev/null
        mv "$CRON_DIR" "${CRON_DIR}_bak_$(date +%s)" 2>/dev/null
        
        # 3. 创建一个新的、干净的目录
        mkdir -p "$CRON_DIR"
        chmod 733 "$CRON_DIR"
        
        # 4. 创建一个空的 root 文件并锁定
        touch "$CRON_FILE"
        chmod 600 "$CRON_FILE"
        chattr +i "$CRON_FILE"
        
        echo -e "${GREEN}已执行目录重构。原恶意任务目录已更名备份。${NC}"
    fi
fi

# --- [2. 内存实时监控进程清理] ---
echo -e "\n${YELLOW}[2. 正在搜寻隐藏的内存监视器]${NC}"
# 寻找那些虽然在运行，但其磁盘执行文件已被删除的进程（典型木马特征）
SUS_PIDS=$(ls -al /proc/*/exe 2>/dev/null | grep "deleted" | awk '{print $1}' | cut -d'/' -f3)
if [ -n "$SUS_PIDS" ]; then
    echo -e "${RED}发现运行中的“幽灵进程” (文件已删但在内存运行):${NC}"
    for pid in $SUS_PIDS; do
        ps -p "$pid" -o comm=
        read -p "是否强制杀掉进程 $pid? (y/n): " k_pid
        [[ "$k_pid" == "y" ]] && kill -9 "$pid"
    done
fi

# --- [3. 锁定 ld.so.preload] ---
if [ -f "/etc/ld.so.preload" ]; then
    echo -e "${RED}清空并锁定劫持配置...${NC}"
    chattr -ai /etc/ld.so.preload 2>/dev/null
    > /etc/ld.so.preload
    chattr +i /etc/ld.so.preload
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${RED}请立即执行: reboot${NC}"
echo -e "${BLUE}====================================================${NC}"
