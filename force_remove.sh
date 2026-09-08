#!/bin/bash

# Oracle VPS 木马粉碎脚本 v3.0 (增强挂载清理版)
# 针对目标: /usr/bin/wbin

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET="/usr/bin/wbin"

echo -e "${YELLOW}开始执行 [高级别] 强力粉碎任务...${NC}"

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误: 必须以 root 运行！${NC}"
    exit 1
fi

# 1. 停止定时任务
systemctl stop cron 2>/dev/null
systemctl stop crond 2>/dev/null

# 2. 核心步骤：强制卸载挂载点 (解决 Device or resource busy)
echo -e "${YELLOW}正在清理内核挂载点 (Unmounting)...${NC}"
# 查找所有与 wbin 相关的挂载点并按倒序排列（先卸载子目录）
grep "$TARGET" /proc/mounts | awk '{print $2}' | sort -r | while read -r mount_point; do
    echo -e "正在卸载: $mount_point"
    umount -f -l "$mount_point" 2>/dev/null
done

# 3. 清理网络命名空间 (netns)
echo -e "${YELLOW}正在清理网络命名空间...${NC}"
if [ -d "$TARGET/exec/netns" ]; then
    find "$TARGET/exec/netns" -type f | xargs -I {} umount -f -l {} 2>/dev/null
fi

# 4. 暴力杀掉残留进程
echo -e "${YELLOW}正在杀掉占用目录的残留进程...${NC}"
lsof "$TARGET" 2>/dev/null | awk 'NR>1 {print $2}' | xargs kill -9 2>/dev/null
ps -ef | grep "$TARGET" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null

# 5. 解除文件锁定属性
echo -e "${YELLOW}正在解除文件锁定...${NC}"
chattr -R -i "$TARGET" 2>/dev/null
chattr -R -a "$TARGET" 2>/dev/null

# 6. 再次尝试删除
echo -e "${YELLOW}正在执行最终粉碎...${NC}"
rm -rf "$TARGET"

# 7. 检查结果
if [ ! -d "$TARGET" ]; then
    echo -e "${GREEN}--------------------------------------${NC}"
    echo -e "${GREEN}成功：$TARGET 已被彻底粉碎并卸载！${NC}"
    echo -e "${GREEN}--------------------------------------${NC}"
else
    echo -e "${RED}--------------------------------------${NC}"
    echo -e "${RED}严重警告：即便卸载了挂载点，删除依然失败。${NC}"
    echo -e "${RED}这说明该木马极可能加载了内核模块 (Rootkit)。${NC}"
    echo -e "${RED}为了您的数据安全，请务必【重装系统】。${NC}"
    echo -e "${RED}--------------------------------------${NC}"
fi

# 恢复 Cron
systemctl start cron 2>/dev/null
