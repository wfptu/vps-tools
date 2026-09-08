#!/bin/bash

# Oracle VPS 专家级安全巡检脚本 v3.0 (终极加固版)
# 针对 wbin 内核挂载木马与 perfcc 持久化木马专项优化

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}        Oracle VPS 专家级安全巡检脚本 v3.0          ${NC}"
echo -e "${BLUE}====================================================${NC}"

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}请以 root 用户运行此脚本！${NC}"
    exit 1
fi

# --- [1. Swap 检查与性能加固] ---
echo -e "\n${YELLOW}[1. 虚拟内存 (Swap) 检查]${NC}"
SWAP_TOTAL=$(free -m | awk '/Swap:/ { print $2 }')
if [ "$SWAP_TOTAL" -eq 0 ]; then
    read -p "未开启 Swap，容易导致 SSH 死机。是否一键开启 2GB Swap? (y/n): " swp_c
    if [[ "$swp_c" == "y" ]]; then
        fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        echo -e "${GREEN}Swap 加固完成。${NC}"
    fi
else
    echo -e "${GREEN}Swap 已开启 ($SWAP_TOTAL MB)。${NC}"
fi

# --- [2. 顽固恶意定时任务清理] ---
echo -e "\n${YELLOW}[2. 恶意定时任务扫描 (含属性解锁)]${NC}"
KEYWORDS="perfcc|perfclean|miner|cryptonight|root/.config|wbin"
# 获取包含关键字的文件列表
SUS_FILES=$(grep -rlE "$KEYWORDS" /etc/cron* /var/spool/cron/crontabs /etc/crontab 2>/dev/null)

if [ -z "$SUS_FILES" ]; then
    echo -e "${GREEN}未发现明显的恶意定时任务。${NC}"
else
    for f in $SUS_FILES; do
        echo -e "--------------------------------------"
        echo -e "发现可疑文件: ${RED}$f${NC}"
        echo -e "内容预览: $(grep -E "$KEYWORDS" "$f" | head -n1)"
        read -p "是否【彻底解锁并清理】此任务? (y/n): " cfm
        if [[ "$cfm" == "y" ]]; then
            # 关键：先解除可能存在的 +i 锁定属性
            chattr -ai "$f" 2>/dev/null
            if [[ "$f" == *"crontabs/root" || "$f" == *"/etc/crontab" ]]; then
                # 强力删除包含关键字的行
                sed -i -E "/$KEYWORDS/d" "$f"
                echo -e "${GREEN}已通过 sed 强制剔除恶意行。${NC}"
            else
                rm -f "$f"
                echo -e "${GREEN}文件已删除。${NC}"
            fi
        fi
    done
fi

# --- [3. 恶意进程与内核挂载点清理] ---
echo -e "\n${YELLOW}[3. 顽固挂载点与进程扫描 (针对 wbin)]${NC}"
WBIN_PATH="/usr/bin/wbin"
if [ -d "$WBIN_PATH" ] || grep -q "$WBIN_PATH" /proc/mounts; then
    echo -e "${RED}检测到 wbin 恶意挂载或文件夹存在！${NC}"
    read -p "是否执行暴力拆解逻辑 (Unmount + Force Delete)? (y/n): " dwbin
    if [[ "$dwbin" == "y" ]]; then
        # 1. 停止定时任务防止干扰
        systemctl stop cron 2>/dev/null
        # 2. 卸载挂载点
        grep "$WBIN_PATH" /proc/mounts | awk '{print $2}' | sort -r | while read -r mnt; do
            umount -f -l "$mnt" 2>/dev/null
        done
        # 3. 杀进程
        ps -ef | grep "$WBIN_PATH" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
        # 4. 解锁并删除
        chattr -R -ai "$WBIN_PATH" 2>/dev/null
        rm -rf "$WBIN_PATH"
        [ ! -d "$WBIN_PATH" ] && echo -e "${GREEN}wbin 文件夹已粉碎。${NC}" || echo -e "${RED}粉碎失败，请检查内核模块！${NC}"
        systemctl start cron 2>/dev/null
    fi
fi

# --- [4. 系统目录篡改检查] ---
echo -e "\n${YELLOW}[4. 系统命令篡改自检]${NC}"
ALTERED=$(find /bin /sbin /usr/bin /usr/sbin -mtime -7 -type f 2>/dev/null)
if [ -z "$ALTERED" ]; then
    echo -e "${GREEN}最近 7 天核心目录无变动。${NC}"
else
    echo -e "${YELLOW}以下文件最近有变动:${NC}"
    for f in $ALTERED; do
        [[ "$f" == *"x-ui"* || "$f" == *"acme"* ]] && continue
        echo -e "可疑变动: ${RED}$f${NC}"
        read -p "是否删除此变动文件? (y/n): " fcfm
        if [[ "$fcfm" == "y" ]]; then
            chattr -ai "$f" 2>/dev/null
            rm -f "$f"
            echo -e "${GREEN}已删除。${NC}"
        fi
    done
fi

# --- [5. 恶意 Systemd 服务检查] ---
echo -e "\n${YELLOW}[5. 恶意 Systemd 服务检查]${NC}"
SUS_SERVICE=$(grep -rE "$KEYWORDS" /etc/systemd/system/ 2>/dev/null | awk -F: '{print $1}' | uniq)
if [ -z "$SUS_SERVICE" ]; then
    echo -e "${GREEN}未发现异常服务。${NC}"
else
    for s in $SUS_SERVICE; do
        echo -e "发现可疑服务文件: ${RED}$s${NC}"
        read -p "是否禁用并删除该服务? (y/n): " scfm
        if [[ "$scfm" == "y" ]]; then
            sname=$(basename "$s")
            systemctl stop "$sname" 2>/dev/null
            systemctl disable "$sname" 2>/dev/null
            chattr -ai "$s" 2>/dev/null
            rm -f "$s"
            echo -e "${GREEN}服务已清理。${NC}"
        fi
    done
fi

# --- [6. SSH 端口与后门钥匙清理] ---
echo -e "\n${YELLOW}[6. SSH 访问策略调整]${NC}"
CUR_PORT=$(grep "Port " /etc/ssh/sshd_config | awk '{print $2}' | head -n1)
: ${CUR_PORT:=22}
echo -e "当前 SSH 端口: ${BLUE}$CUR_PORT${NC}"
read -p "是否修改端口? (y/n): " p_c
if [[ "$p_c" == "y" ]]; then
    read -p "输入新端口 (10000-65535): " NEW_P
    sed -i "s/^#Port .*/Port $NEW_P/" /etc/ssh/sshd_config
    sed -i "s/^Port .*/Port $NEW_P/" /etc/ssh/sshd_config
    echo -e "${RED}记得去甲骨文后台放行 $NEW_P 端口！${NC}"
    read -p "是否重启 SSH 生效? (y/n): " r_s
    [[ "$r_s" == "y" ]] && systemctl restart ssh && echo -e "${GREEN}SSH 已重启。${NC}"
fi

AK="/root/.ssh/authorized_keys"
if [ -f "$AK" ]; then
    echo -e "\n当前 SSH 后门钥匙检查:"
    cat -n "$AK"
    read -p "是否清空所有已授权公钥 (防止后门)? (y/n): " c_ak
    [[ "$c_ak" == "y" ]] && > "$AK" && echo -e "${GREEN}已清空公钥。${NC}"
fi

echo -e "\n${BLUE}====================================================${NC}"
echo -e "${GREEN}全部巡检加固流程结束！${NC}"
echo -e "${BLUE}====================================================${NC}"
