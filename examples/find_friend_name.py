"""Helper: Find the exact friend remark name by search."""

from __future__ import annotations

import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin import Navigator

print("=" * 60)
print("查找好友备注名（精确匹配）")
print("=" * 60)
print()
print("提示：这个工具会帮你找到好友的精确备注名")
print("      （包括所有空格、特殊字符）")
print()

keyword = input("请输入搜索关键词（例如：第七人格）: ").strip()
if not keyword:
    print("✗ 未输入关键词，退出")
    sys.exit(1)

print()
print(f"正在搜索包含 '{keyword}' 的好友...")
print("（观察微信窗口，会自动搜索）")
print()

try:
    # This will open WeChat and search
    # User can manually see the exact friend name in WeChat search results
    print("操作步骤：")
    print("1. 等待微信自动打开搜索框")
    print("2. 搜索结果会显示在微信窗口中")
    print("3. 请查看搜索结果中的好友备注，精确复制")
    print()
    print("提示：可以在微信中右键好友 → 查看资料 → 查看完整备注")
    print()
    input("按 Enter 继续...")

    # Open WeChat main window
    from pyweixin.WeChatAuto import Contacts
    main_window = Navigator.open_main_window(is_maximize=False)

    # Open search
    import pyautogui
    from pyweixin.WinSettings import SystemSettings

    search = main_window.descendants(control_type="Edit", title="搜索")
    if search:
        search[0].click_input()
        SystemSettings.copy_text_to_windowsclipboard(keyword)
        pyautogui.hotkey('ctrl', 'v')

        print()
        print("=" * 60)
        print("✓ 已在微信中搜索，请查看搜索结果")
        print("=" * 60)
        print()
        print("下一步：")
        print("1. 在微信搜索结果中找到目标好友")
        print("2. 精确复制好友的备注名（注意空格和特殊字符）")
        print("3. 粘贴到测试脚本中使用")
        print()
        print("常见好友名格式：")
        print("  - 第七人格沉浸式剧场-深南店")
        print("  - 第七人格深南店客服")
        print("  - 第七人格 深南店")
        print()
        input("复制好友名后按 Enter 关闭...")

        main_window.close()
    else:
        print("✗ 无法打开搜索框")

except Exception as exc:
    print(f"✗ 错误: {exc}")
    print()
    print("建议：手动在微信中搜索好友，复制备注名")
