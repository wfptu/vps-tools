#!/bin/bash

# Oracle VPS 木马粉碎脚本 v4.0 (内核级清理版)
TARGET="/usr/bin/wbin"

echo "正在执行深度内核级清理..."

# 1. 强力停掉可能被寄生的服务
systemctl stop docker containerd snapd 2>/dev/null

# 2. 暴力清理网络命名空间 (这是导致 Device busy 的主因)
echo "清理网络命名空间..."
if command -v ip >/dev/null 2>&1; then
    for ns in $(ip netns list | awk '{print $1}'); do
        ip netns delete "$ns" 2>/dev/null
    done
fi

# 3. 找出所有正在占用 wbin 的进程并直接从内核层面杀死
echo "暴力清除占用进程..."
lsof | grep "$TARGET" | awk '{print $2}' | sort -u | xargs -r kill -9 2>/dev/null

# 4. 强制卸载挂载点（使用更底层的 mountinfo 扫描）
echo "从内核底层剥离挂载点..."
tac /proc/self/mountinfo | grep "$TARGET" | awk '{print $5}' | while read -r mnt; do
    echo "强制卸载: $mnt"
    umount -f -l "$mnt" 2>/dev/null
done

# 5. 尝试解除锁定并彻底删除
echo "尝试执行最终删除..."
chattr -R -i "$TARGET" 2>/dev/null
chattr -R -a "$TARGET" 2>/dev/null
rm -rf "$TARGET"

# 6. 最后的验证
if [ ! -d "$TARGET" ]; then
    echo "！！！成功：$TARGET 已被铲除！！！"
    echo "请立即重启服务器：reboot"
else
    echo "！！！严重警告：清理失败！！！"
fi
