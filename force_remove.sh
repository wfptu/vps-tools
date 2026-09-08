#!/bin/bash

# Oracle VPS 顽固木马文件夹强力粉碎脚本
# 针对目标: /usr/bin/wbin

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET="/usr/bin/wbin"

echo -e "${YELLOW}开始执行强力粉碎任务...${NC}"

# 1. 检查 root 权限
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误: 必须以 root 用户运行！${NC}"
    exit 1
fi

# 2. 检查目录是否存在
if [ ! -d "$TARGET" ]; then
    echo -e "${GREEN}目录 $TARGET 不存在，无需处理。${NC}"
    exit 0
fi

# 3. 暂时停止 Cron 服务，防止删除过程中木马复活
echo -e "${YELLOW}正在暂时停止定时任务服务...${NC}"
systemctl stop cron 2>/dev/null
systemctl stop crond 2>/dev/null

# 4. 解除文件系统锁定 (chattr)
echo -e "${YELLOW}正在解除文件锁定属性 (Immutable Attribute)...${NC}"
if command -v chattr >/dev/null 2>&1; then
    # 解除目录及内部所有文件的 i 和 a 属性
    chattr -R -i "$TARGET" 2>/dev/null
    chattr -R -a "$TARGET" 2>/dev/null
    chattr -i "$TARGET" 2>/dev/null
else
    echo -e "${RED}警告: 未找到 chattr 命令，尝试安装...${NC}"
    apt-get update && apt-get install e2fsprogs -y
    chattr -R -i "$TARGET" 2>/dev/null
fi

# 5. 杀掉正在使用该目录的进程
echo -e "${YELLOW}正在清理占用该目录的恶意进程...${NC}"
if command -v fuser >/dev/null 2>&1; then
    fuser -k -9 -m "$TARGET" 2>/dev/null
else
    # 如果没有 fuser，尝试通过 ps 查找并杀掉包含 wbin 路径的进程
    ps -ef | grep "$TARGET" | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
fi

# 6. 执行强力删除
echo -e "${YELLOW}正在执行删除操作...${NC}"
rm -rf "$TARGET"

# 7. 验证删除结果
if [ ! -d "$TARGET" ]; then
    echo -e "${GREEN}--------------------------------------${NC}"
    echo -e "${GREEN}成功：$TARGET 已被彻底粉碎！${NC}"
    echo -e "${GREEN}--------------------------------------${NC}"
else
    echo -e "${RED}--------------------------------------${NC}"
    echo -e "${RED}失败：$TARGET 依然存在。${NC}"
    echo -e "${YELLOW}可能原因：木马已注入内核或修改了 rm 命令。${NC}"
    echo -e "${RED}--------------------------------------${NC}"
fi

# 8. 恢复 Cron 服务
echo -e "${YELLOW}正在恢复定时任务服务...${NC}"
systemctl start cron 2>/dev/null
systemctl start crond 2>/dev/null

echo -e "${GREEN}任务结束。${NC}"
