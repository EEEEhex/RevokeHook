#!/bin/bash
# 微信(4.1.13.23) 防撤回：启动并自动注入脚本
set -u

WEIXIN=/opt/wechat/wechat
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"   # scripts/
ROOT="$(dirname "$SCRIPT_DIR")"                  # 仓库根目录
INJECTOR="$ROOT/src/injector/injector"
SO="$ROOT/src/hook/librevokehook.so"

# 1. 若微信未运行则启动
if ! pgrep -x wechat >/dev/null 2>&1; then
    echo "[*] 启动微信..."
    setsid nohup "$WEIXIN" >/dev/null 2>&1 &
    echo "[*] 等待微信初始化 (8s)..."
    sleep 8
fi

# 2. 获取微信主进程 PID（排除 crashpad_handler 等子进程）
PID=$(pgrep -x wechat | head -1)
if [ -z "$PID" ]; then
    echo "[-] 错误：未能找到微信主进程"
    exit 1
fi
echo "[*] 微信主进程 PID=$PID"

# 3. 检查是否已注入，避免重复
if grep -q librevokehook "/proc/$PID/maps" 2>/dev/null; then
    echo "[+] 已注入防撤回，无需重复操作 (PID=$PID)"
    exit 0
fi

# 4. 注入
echo "[*] 注入 librevokehook.so ..."
sudo "$INJECTOR" -p "$PID" "$SO"
RC=$?

# 5. 输出日志
LOG="${XDG_CACHE_HOME:-$HOME/.cache}/revokehook.log"
if [ -f "$LOG" ]; then
    echo "---- 防撤回日志 ----"
    cat "$LOG"
else
    echo "[!] 未找到日志：$LOG"
fi

echo "注入结果退出码=$RC"
if [ $RC -eq 0 ]; then
    echo "[+] 防撤回已生效（PID=$PID）"
else
    echo "[-] 注入失败，请检查错误"
fi
exit $RC