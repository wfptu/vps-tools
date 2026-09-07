#!/bin/bash

# Oracle VPS 专家级安全巡检交互脚本 v2.0
# 修复了交互逻辑，支持逐个清理恶意任务与篡改文件

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}        Oracle VPS 专家级安全巡检脚本 v2.0          ${NC}"
echo -e "${BLUE}====================================================${NC}"

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}请以 root 用户运行此脚本！${NC}"
    exit 1
fi

# --- [1. Swap 检查] ---
echo -e "\n${YELLOW}[1. 虚拟内存 (Swap) 检查]${NC}"
SWAP_TOTAL=$(free -m | awk '/Swap:/ { print $2 }')
if [ "$SWAP_TOTAL" -eq 0 ]; then
    read -p "未开启 Swap，容易导致 SSH 死机。是否创建 2GB Swap? (y/n): " swp_c
    if [[ "$swp_c" == "y" ]]; then
        fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        echo -e "${GREEN}Swap 已开启。${NC}"
    fi
else
    echo -e "${GREEN}Swap 已开启 ($SWAP_TOTAL MB)。${NC}"
fi

# --- [2. 恶意定时任务清理] ---
echo -e "\n${YELLOW}[2. 恶意定时任务清理]${NC}"
KEYWORDS="perfcc|perfclean|miner|cryptonight|root/.config"
# 使用 grep -l 只列出文件名，并存入数组
SUS_FILES=$(grep -rlE "$KEYWORDS" /etc/cron* /var/spool/cron/crontabs 2>/dev/null)

if [ -z "$SUS_FILES" ]; then
    echo -e "${GREEN}未发现明显的恶意定时任务。${NC}"
else
    echo -e "${RED}警告：发现以下可疑定时任务文件！${NC}"
    for f in $SUS_FILES; do
        echo -e "--------------------------------------"
        echo -e "文件: ${BLUE}$f${NC}"
        echo -e "内容预览: $(grep -E "$KEYWORDS" "$f" | head -n1)"
        read -p "是否删除此任务? (y/n): " cfm
        if [[ "$cfm" == "y" ]]; then
            if [[ "$f" == *"crontabs/root" ]]; then
                # 如果是 root 的主 crontab，只清理恶意行
                (crontab -l | grep -vE "$KEYWORDS") | crontab -
                echo -e "${GREEN}已清理 root 任务中的恶意记录。${NC}"
            else
                rm -f "$f"
                echo -e "${GREEN}已删除文件: $f${NC}"
            fi
        fi
    done
fi

# --- [3. 系统目录篡改检查与清理] ---
echo -e "\n${YELLOW}[3. 系统关键目录篡改检查]${NC}"
echo -e "正在扫描 /bin /usr/bin 最近 7 天变动的文件..."
# 排除一些常见的正常变动文件
ALTERED=$(find /bin /sbin /usr/bin /usr/sbin -mtime -7 -type f 2>/dev/null)

if [ -z "$ALTERED" ]; then
    echo -e "${GREEN}未发现最近篡改的文件。${NC}"
else
    echo -e "${RED}发现以下最近变动的文件（极度可疑）：${NC}"
    for f in $ALTERED; do
        # 排除掉 x-ui，避免误删
        if [[ "$f" == *"x-ui"* ]]; then
            echo -e "${YELLOW}[忽略]${NC} 正常服务文件: $f"
            continue
        fi

        echo -e "--------------------------------------"
        echo -e "可疑文件: ${RED}$f${NC}"
        read -p "是否彻底删除此文件? (y/n): " fcfm
        if [[ "$fcfm" == "y" ]]; then
            rm -f "$f"
            echo -e "${GREEN}已删除文件: $f${NC}"
        fi
    done
fi

# 特别检查本次发现的 wbin 恶意文件夹
if [ -d "/usr/bin/wbin" ]; then
    echo -e "\n${RED}检测到恶意文件夹 /usr/bin/wbin (通常是木马存放处)${NC}"
    read -p "是否递归删除整个 /usr/bin/wbin 文件夹? (y/n): " dwbin
    if [[ "$dwbin" == "y" ]]; then
        rm -rf /usr/bin/wbin
        echo -e "${GREEN}已清理恶意文件夹。${NC}"
    fi
fi

# --- [4. SSH 端口修改] ---
echo -e "\n${YELLOW}[4. SSH 端口加固]${NC}"
CUR_PORT=$(grep "Port " /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
: ${CUR_PORT:=22}
echo -e "当前 SSH 端口: ${BLUE}$CUR_PORT${NC}"
read -p "是否修改端口以躲避扫描? (y/n): " p_c
if [[ "$p_c" == "y" ]]; then
    read -p "输入新端口 (10000-65535): " NEW_P
    sed -i "s/^#Port .*/Port $NEW_P/" /etc/ssh/sshd_config
    sed -i "s/^Port .*/Port $NEW_P/" /etc/ssh/sshd_config
    echo -e "${RED}请确认甲骨文后台已放行 $NEW_P 端口！${NC}"
    read -p "是否现在重启 SSH 服务? (y/n): " r_s
    [[ "$r_s" == "y" ]] && systemctl restart ssh && echo -e "${GREEN}SSH 已重启。${NC}"
fi

# --- [5. SSH 公钥检查] ---
echo -e "\n${YELLOW}[5. SSH 后门公钥检查]${NC}"
AK="/root/.ssh/authorized_keys"
if [ -f "$AK" ]; then
    echo -e "当前公钥列表:"
    cat -n "$AK"
    read -p "是否清空公钥(防止黑客留后门)? (y/n): " c_ak
    [[ "$c_ak" == "y" ]] && > "$AK" && echo -e "${GREEN}公钥已清空。${NC}"
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}巡检完成！${NC}"
echo -e "${BLUE}====================================================${NC}"
