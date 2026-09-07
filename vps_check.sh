#!/bin/bash

# Oracle VPS 专家级自动巡检与加固交互脚本
# 支持：资源监控、Swap加固、交互式木马清理、SSH端口修改

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}        Oracle VPS 专家级安全巡检交互脚本            ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. 检查 root 权限
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}请以 root 用户运行此脚本！${NC}"
    exit 1
fi

# 2. 资源状态检查
echo -e "\n${YELLOW}[1. 系统资源状态预览]${NC}"
UPTIME=$(uptime -p)
LOAD=$(uptime | awk -F'load average:' '{ print $2 }')
MEM_FREE=$(free -m | awk '/Mem:/ { print $4 }')
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}')
echo -e "运行时间: $UPTIME"
echo -e "负载情况: $LOAD"
echo -e "剩余内存: ${MEM_FREE}MB"
echo -e "磁盘占用: $DISK_USAGE"

# 3. Swap 交互检查
echo -e "\n${YELLOW}[2. 虚拟内存 (Swap) 检查]${NC}"
SWAP_TOTAL=$(free -m | awk '/Swap:/ { print $2 }')
if [ "$SWAP_TOTAL" -eq 0 ]; then
    echo -e "${RED}警告: 当前未开启 Swap，小内存机型极易死机！${NC}"
    read -p "是否立即创建 2GB 虚拟内存? (y/n): " choice
    if [[ "$choice" == "y" ]]; then
        fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        echo -e "${GREEN}Swap 创建成功！${NC}"
    fi
else
    echo -e "${GREEN}Swap 已开启，当前容量: ${SWAP_TOTAL}MB${NC}"
fi

# 4. 交互式定时任务(木马)扫描
echo -e "\n${YELLOW}[3. 恶意定时任务扫描]${NC}"
# 常见木马关键词
KEYWORDS="perfcc|http|curl|wget|miner|cryptonight"
SUSPICIOUS=$(grep -rE "$KEYWORDS" /etc/cron* /var/spool/cron/crontabs 2>/dev/null)

if [ -n "$SUSPICIOUS" ]; then
    echo -e "${RED}发现可疑定时任务记录:${NC}"
    echo "$SUSPICIOUS" | while read -r line; do
        FILE=$(echo "$line" | cut -d: -f1)
        CONTENT=$(echo "$line" | cut -d: -f2-)
        echo -e "\n待处理文件: ${BLUE}$FILE${NC}"
        echo -e "内容: $CONTENT"
        read -p "是否删除该文件/记录? (y/n): " del_choice
        if [[ "$del_choice" == "y" ]]; then
            if [[ "$FILE" == *"crontabs/root"* ]]; then
                echo -e "${YELLOW}正在尝试清理 root crontab 中的恶意行...${NC}"
                # 精确删除包含关键字的行
                (crontab -l | grep -vE "$KEYWORDS") | crontab -
            else
                rm -f "$FILE"
                echo -e "${GREEN}文件 $FILE 已删除${NC}"
            fi
        fi
    done
else
    echo -e "${GREEN}未发现明显的恶意定时任务。${NC}"
fi

# 5. 系统关键命令完整性检查
echo -e "\n${YELLOW}[4. 系统命令篡改检查]${NC}"
# 检查最近 7 天内被修改过的系统命令
ALTERED=$(find /bin /usr/bin -mtime -7 -type f)
if [ -n "$ALTERED" ]; then
    echo -e "${RED}警告: 以下核心命令在最近 7 天内被修改过，可能已被植入后门:${NC}"
    echo "$ALTERED"
else
    echo -e "${GREEN}核心系统命令日期正常。${NC}"
fi

# 6. 交互式 SSH 端口修改
echo -e "\n${YELLOW}[5. SSH 安全策略调整]${NC}"
CURRENT_PORT=$(grep "Port " /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
[ -z "$CURRENT_PORT" ] && CURRENT_PORT=22
echo -e "当前 SSH 端口: ${BLUE}$CURRENT_PORT${NC}"

read -p "是否需要修改 SSH 端口? (y/n): " port_choice
if [[ "$port_choice" == "y" ]]; then
    read -p "请输入新的端口号 (建议 10000-65535): " NEW_PORT
    if [[ "$NEW_PORT" =~ ^[0-9]+$ ]]; then
        sed -i "s/^#Port .*/Port $NEW_PORT/" /etc/ssh/sshd_config
        sed -i "s/^Port .*/Port $NEW_PORT/" /etc/ssh/sshd_config
        echo -e "${GREEN}端口已配置为 $NEW_PORT。${NC}"
        echo -e "${RED}注意：请务必在甲骨文后台安全列表开放 TCP $NEW_PORT 端口后再重启 SSH！${NC}"
        read -p "现在重启 SSH 服务吗? (y/n): " restart_ssh
        if [[ "$restart_ssh" == "y" ]]; then
            systemctl restart ssh
            echo -e "${GREEN}SSH 服务已重启。${NC}"
        fi
    else
        echo -e "${RED}输入无效，取消修改。${NC}"
    fi
fi

# 7. SSH 免密登录后门检查
echo -e "\n${YELLOW}[6. SSH 后门钥匙检查]${NC}"
AUTH_FILE="/root/.ssh/authorized_keys"
if [ -f "$AUTH_FILE" ]; then
    echo -e "当前已有的 SSH 公钥:"
    cat -n "$AUTH_FILE"
    read -p "是否清空所有已授权的公钥? (y/n): " clear_ssh
    if [[ "$clear_ssh" == "y" ]]; then
        > "$AUTH_FILE"
        echo -e "${GREEN}公钥已清空。${NC}"
    fi
else
    echo -e "${GREEN}未发现 SSH 公钥文件。${NC}"
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}巡检完成！建议定期运行此脚本。${NC}"
echo -e "${BLUE}====================================================${NC}"
