"""Diagnose WeChat installation and accessibility."""

from __future__ import annotations

import os
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

print("=" * 60)
print("微信环境诊断工具")
print("=" * 60)
print()

# Check 1: WeChat process
print("[1/5] 检查微信进程...")
try:
    import psutil
    wechat_processes = []
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name=(proc.info.get('name') or '').lower()
            if 'wechat' in name or 'weixin' in name:
                wechat_processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if wechat_processes:
        print("  [OK] 微信进程正在运行")
        for p in wechat_processes:
            print(f"    - {p['name']}: {p['exe']}")
    else:
        print("  [ERROR] 未找到微信进程")
        print("    建议: 请先启动微信")
except ImportError:
    print("  [WARN] 未安装 psutil，跳过进程检查")
    print("    安装: pip install psutil")

print()

# Check 2: WeChat window
print("[2/5] 检查微信窗口...")
try:
    from pywinauto import Desktop

    windows = Desktop(backend='uia').windows()
    wechat_windows = []
    for win in windows:
        try:
            title = win.window_text()
            class_name = win.class_name()
            if '微信' in title or 'WeChat' in title or 'WeChatMainWndForPC' in class_name:
                wechat_windows.append({
                    'title': title,
                    'class_name': class_name,
                    'visible': win.is_visible(),
                    'enabled': win.is_enabled()
                })
        except:
            pass

    if wechat_windows:
        print("  [OK] 找到微信窗口")
        for w in wechat_windows:
            print(f"    - 标题: {w['title']}")
            print(f"      类名: {w['class_name']}")
            print(f"      可见: {w['visible']}")
            print(f"      启用: {w['enabled']}")
    else:
        print("  [ERROR] 未找到微信窗口")
        print("    建议: 请确保微信已打开并登录")
except Exception as exc:
    print(f"  [ERROR] 检查失败: {exc}")

print()

# Check 3: Try to open WeChat using Navigator
print("[3/5] 尝试使用 Navigator 打开微信...")
try:
    from pyweixin import Navigator
    print("  正在尝试打开微信主窗口...")
    main_window = Navigator.open_weixin(is_maximize=False)
    print(f"  [OK] 成功打开微信窗口")
    print(f"    - 标题: {main_window.window_text()}")
    print(f"    - 类名: {main_window.class_name()}")
    main_window.close()
except Exception as exc:
    print(f"  [ERROR] 打开失败: {exc}")
    print("    这可能是主要问题所在")

print()

# Check 4: Check WeChat version
print("[4/5] 检查微信版本...")
try:
    import winreg

    # Check registry for WeChat installation
    paths = [
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WeChat",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WeChat",
    ]

    version_found = False
    for path in paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            version = winreg.QueryValueEx(key, "DisplayVersion")[0]
            install_location = winreg.QueryValueEx(key, "InstallLocation")[0]
            print(f"  [OK] 微信已安装")
            print(f"    - 版本: {version}")
            print(f"    - 路径: {install_location}")
            version_found = True
            winreg.CloseKey(key)
            break
        except:
            continue

    if not version_found:
        print("  [WARN] 无法从注册表读取版本信息")
except Exception as exc:
    print(f"  [WARN] 检查失败: {exc}")

print()

# Check 5: Dependencies
print("[5/5] 检查依赖库...")
deps = [
    ('pywinauto', 'pywinauto', 'UI自动化核心库'),
    ('pyautogui', 'pyautogui', '键鼠模拟库'),
    ('win32api', 'pywin32', 'Windows API库'),
    ('psutil', 'psutil', '进程管理库（可选）'),
]

for import_name, display_name, desc in deps:
    try:
        __import__(import_name)
        print(f"  [OK] {display_name}: {desc}")
    except ImportError:
        print(f"  [ERROR] {display_name}: {desc} - 未安装")

print()
print("=" * 60)
print("诊断完成")
print("=" * 60)
print()

print("常见问题解决方案：")
print()
print("1. 如果未找到微信进程/窗口:")
print("   - 手动启动微信并登录")
print()
print("2. 如果 Navigator.open_weixin 失败:")
print("   - 确保微信在前台可见（不要最小化）")
print("   - 尝试重启微信")
print()
print("3. 如果版本不兼容:")
print("   - 确认微信版本是 4.1+")
print("   - 更新 pyweixin 到最新版")
print()
print("4. 如果缺少依赖:")
print("   - pip install -r requirements.txt")
print()

input("按 Enter 退出...")
