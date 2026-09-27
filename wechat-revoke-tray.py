#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
微信防撤回 · 系统托盘状态指示器
在系统托盘显示状态图标，提示微信防撤回是否生效。
状态：
  红色 + 对勾 = 微信运行中且防撤回已注入
  黄色 + 叹号 = 微信运行中但未注入
  灰色 + 圆点 = 微信未运行

左键点击图标：微信未注入/未运行时弹出对话框，可选“尝试防撤回”。
依赖: PyQt6 (pip install --user PyQt6)
"""
import os
import subprocess
import sys

# 使用 wayland 平台：实测 Qt 的 xcb 平台下托盘左键不产生 activated 信号，
# 而 wayland 平台左键能正常触发。左键操作改用系统通知+直接动作，不依赖
# 菜单/对话框定位（wayland 下更可靠）。
_session_type = os.environ.get("XDG_SESSION_TYPE", "")
os.environ["QT_QPA_PLATFORM"] = (
    os.environ.get("QT_QPA_PLATFORM")
    or ("wayland" if "wayland" in _session_type else "xcb")
)

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QCursor, QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PyQt6.QtWidgets import QApplication, QMenu, QMessageBox, QSystemTrayIcon

INJECT_SCRIPT = os.path.expanduser("~/桌面/RevokeHook/linux-wechat-防撤回.sh")
REVOKE_MARK = "librevokehook"


def wechat_status():
    """返回 (微信主进程PID or None, 是否已注入)"""
    try:
        out = subprocess.run(
            ["pgrep", "-x", "wechat"], capture_output=True, text=True, timeout=3
        ).stdout.strip().split()
    except Exception:
        out = []
    if not out:
        return None, False
    pid = out[0]
    try:
        with open(f"/proc/{pid}/maps", "r", errors="ignore") as f:
            injected = REVOKE_MARK in f.read()
    except Exception:
        injected = False
    return pid, injected


def make_icon(mode):
    """mode: 'on'(红勾) / 'warn'(黄叹) / 'off'(灰点)"""
    size = 64
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    color = QColor("#d33838") if mode == "on" else (
        QColor("#e6a23c") if mode == "warn" else QColor("#9a9a9a"))
    # 圆形底
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(color)
    p.drawEllipse(6, 6, 52, 52)
    # 白色符号
    pen = QPen(QColor("#ffffff"))
    pen.setWidth(6)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    if mode == "on":
        path = QPainterPath()
        path.moveTo(20, 34)
        path.lineTo(28, 42)
        path.lineTo(45, 22)
        p.drawPath(path)
    elif mode == "warn":
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#ffffff"))
        p.drawRoundedRect(30, 18, 5, 18, 2, 2)
        p.drawEllipse(29, 42, 6, 6)
    else:
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(27, 27, 10, 10)
    p.end()
    return QIcon(pm)


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    tray = QSystemTrayIcon()
    tray.setIcon(make_icon("off"))

    menu = QMenu()
    act_run = QAction("启动微信并注入防撤回", tray)
    act_show = QAction("刷新状态", tray)
    act_quit = QAction("退出指示器", tray)
    menu.addAction(act_run)
    menu.addAction(act_show)
    menu.addSeparator()
    menu.addAction(act_quit)
    tray.setContextMenu(menu)

    def refresh():
        pid, injected = wechat_status()
        if pid:
            if injected:
                tray.setIcon(make_icon("on"))
                tray.setToolTip(
                    f"微信防撤回 · 已开启\nPID: {pid}\n撤回删除与消息入库钩子已注入")
            else:
                tray.setIcon(make_icon("warn"))
                tray.setToolTip(
                    f"微信防撤回 · 未注入\nPID: {pid}\n请点击菜单“启动微信并注入防撤回”")
        else:
            tray.setIcon(make_icon("off"))
            tray.setToolTip("微信防撤回 · 微信未运行\n"
                            "可点击菜单“启动微信并注入防撤回”")

    def run_and_hook():
        os.system(f'nohup "{INJECT_SCRIPT}" >/dev/null 2>&1 &')

    def on_activated(reason):
        # 左键(Trigger)点击：未注入/未运行则尝试防撤回，已注入则提示
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            pid, injected = wechat_status()
            if pid and injected:
                tray.showMessage(
                    "微信防撤回", f"已开启（PID {pid}）",
                    QSystemTrayIcon.MessageIcon.Information, 2500)
            else:
                run_and_hook()
                tray.showMessage(
                    "微信防撤回",
                    ("正在启动微信并注入防撤回..." if not pid
                     else "已重新注入防撤回，请稍候..."),
                    QSystemTrayIcon.MessageIcon.Information, 3000)
            refresh()

    act_run.triggered.connect(run_and_hook)
    act_show.triggered.connect(refresh)
    act_quit.triggered.connect(app.quit)
    tray.activated.connect(on_activated)

    tray.show()
    refresh()
    print(f"[diag] systemTrayAvailable={QSystemTrayIcon.isSystemTrayAvailable()} "
          f"visible={tray.isVisible()}", flush=True)
    timer = QTimer()
    timer.timeout.connect(refresh)
    timer.start(5000)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()