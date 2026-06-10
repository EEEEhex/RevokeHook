# RevokeHook Linux

## 编译方法
`make clean && make`

## 使用方法
执行 `./RevokeHookTUI` 
  
<img width="2541" height="1240" alt="image" src="https://github.com/user-attachments/assets/bbba6df6-5e80-4632-8417-67999abc3a89" />  

### 自动注入
如果是使用flatpak安装的, 点击'创建快捷方式'将直接把带注入命令的.desktop创建到桌面上  

### 手动注入
**flatpak**  
运行 `./injector -f com.tencent.WeChat -s ./librevokehook.so --env=REVOKEHOOK_INI=/your_path/RevokeHookTUI/RevokeHook.ini`  
注意:  
1. 不要使用sudo
2. REVOKEHOOK_INI指向的路径要允许flatpak沙箱使用  

**其他安装形式(未测试)**  
运行 `cp -r RevokeHook.ini ~/.config/RevokeHook/RevokeHook.ini`   
注入 `sudo ./injector -p {PID} ./librevokehook.so`  
注意:   
1. 要使用sudo
2. 使用的PID是wechat主进程的pid
3. RevokeHook.ini必须放到`~/.config/RevokeHook/RevokeHook.ini`

## 日志排查
flatpak的日志会放在`cat ~/.var/app/com.tencent.WeChat/cache/revokehook.log`  
其他安装形式的日志会放在`cat /tmp/revokehook.log`
