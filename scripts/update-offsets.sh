#!/bin/bash
# 微信(4.1.13.23+) 防撤回：一键重新计算偏移并更新 RevokeHook.ini
# 用法：./update-offsets.sh [版本号]
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"        # scripts/
ROOT="$(dirname "$SCRIPT_DIR")"                    # 仓库根目录
SEARCH_PROJ="$ROOT/src/searchoffsets"
WEIXIN=/opt/wechat/wechat
INI="$HOME/.config/RevokeHook/RevokeHook.ini"
INJECT_SCRIPT="$ROOT/scripts/launch-wechat.sh"

# ---------- 1. 确定微信版本 ----------
VERSION=""
if [ $# -ge 1 ] && [ -n "$1" ]; then
    VERSION="$1"
else
    PKG_VER=$(pacman -Q wechat-bin 2>/dev/null | awk '{print $2}' | cut -d- -f1)
    if [ -n "$PKG_VER" ]; then
        VERSION="$PKG_VER"
    else
        echo "[-] 无法自动判断微信版本，请手动指定：$0 <版本号>"
        exit 1
    fi
fi
echo "[*] 微信版本: $VERSION"

# ---------- 2. 定位 Config3.json 与程序 ----------
CONFIG3="$ROOT/Config3.json"
[ -f "$CONFIG3" ] || CONFIG3="$SEARCH_PROJ/Config3.json"
if [ ! -f "$CONFIG3" ]; then
    echo "[-] 找不到 Config3.json"
    exit 1
fi
echo "[*] Config3: $CONFIG3"

if [ ! -d "$SEARCH_PROJ" ]; then
    echo "[-] 找不到 searchoffsets 工程目录: $SEARCH_PROJ"
    exit 1
fi

# ---------- 3. 编译并运行搜索 ----------
echo "[*] 确保 searchoffsets 已编译..."
( cd "$SEARCH_PROJ" && dotnet build -c Release >/dev/null 2>&1 )
DLL="$SEARCH_PROJ/bin/Release/net8.0/searchoffsets.dll"
if [ ! -f "$DLL" ]; then
    echo "[-] 编译失败：未生成 $DLL"
    exit 1
fi

echo "[*] 开始计算偏移（反汇编微信二进制，约1-2分钟）..."
OUT=$(dotnet "$DLL" "$WEIXIN" "$VERSION" "$CONFIG3" 2>&1)
RC=$?
echo "$OUT" | grep -E "DelMsgOffset|Add2DBOffset|未在|未找到|搜索失败|失败" | head -20

DEL=$(echo "$OUT" | grep -oP 'DelMsgOffset=\K[0-9]+' | head -1)
ADD=$(echo "$OUT" | grep -oP 'Add2DBOffset=\K[0-9]+' | head -1)

if [ -z "$DEL" ] || [ -z "$ADD" ]; then
    echo "[-] 未计算到有效偏移量，退出码=$RC。输出如下："
    echo "$OUT" | tail -25
    exit 2
fi
echo "[*] 计算结果: DelMsgOffset=$DEL  Add2DBOffset=$ADD"

# ---------- 4. 更新 RevokeHook.ini（保留原 Setting） ----------
mkdir -p "$(dirname "$INI")"
OLD_SETTING=""
if [ -f "$INI" ]; then
    OLD_SETTING=$(awk '/\[Setting\]/{f=1} f&&/^[A-Za-z]/{print}' "$INI" | grep -v '^Ver=')
fi

{
    echo "[KeyFunc]"
    echo "DelMsgOffset=$DEL"
    echo "Add2DBOffset=$ADD"
    echo ""
    echo "[Setting]"
    if [ -n "$OLD_SETTING" ]; then
        echo "$OLD_SETTING"
    else
        echo "AutoRun=false"
        echo "OverTip=false"
        echo "AntiRevokeSelf=false"
        echo "OutputDebugMsg=false"
    fi
    echo "Ver=$VERSION"
} > "$INI"

echo "[+] 已更新: $INI"
echo "------------------------------------------------"
cat "$INI"
echo "------------------------------------------------"

# ---------- 5. 提示下一步 ----------
if pgrep -x wechat >/dev/null 2>&1; then
    WPID=$(pgrep -x wechat | head -1)
    if grep -q librevokehook "/proc/$WPID/maps" 2>/dev/null; then
        echo "[!] 微信当前已运行且已注入，需重启微信并重跑防撤回脚本后新偏移才生效。"
    else
        echo "[!] 微信正在运行但未注入，请运行：$INJECT_SCRIPT"
    fi
else
    echo "[*] 微信未运行，下次用防撤回脚本/开机自启启动时自动用新偏移注入。"
fi
exit 0