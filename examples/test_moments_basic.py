"""Quick test: fetch 1 moment to verify basic functionality."""

from __future__ import annotations

import os
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin import Moments

print("=" * 60)
print("微信朋友圈基础功能测试")
print("=" * 60)
print()

friend = input("请输入好友备注（例如：第七人格深南店客服）: ").strip()
if not friend:
    print("[ERROR] 未输入好友备注，退出")
    sys.exit(1)

# 创建输出目录（使用绝对路径）
output_dir = os.path.join(os.getcwd(), "test_moments_output")
os.makedirs(output_dir, exist_ok=True)

print()
print(f"[1/2] 正在测试获取好友 '{friend}' 的最新1条朋友圈...")
print(f"  输出目录: {output_dir}")
print("  提示: 观察微信窗口是否自动打开")
print()

try:
    posts = Moments.dump_friend_moments(
        friend=friend,
        number=1,
        save_detail=True,
        target_folder=output_dir,
        is_maximize=False,
        close_weixin=False,
    )
    print(f"[2/2] [OK] 成功！抓取到 {len(posts)} 条朋友圈")
    print()
    if posts:
        post = posts[0]
        print("内容预览:")
        print("  发布时间:", post.get("发布时间", ""))
        print("  内容:", post.get("内容", "")[:100])
        print("  图片数量:", post.get("图片数量", 0))
        print("  视频数量:", post.get("视频数量", 0))
    print()
    print("=" * 60)
    print("[OK] 基础功能正常！可以开始采集历史题目了")
    print("提示: 本次测试默认不关闭微信窗口，便于观察自动化过程")
    print("=" * 60)
except Exception as exc:
    print(f"[ERROR] 错误: {exc}")
    print()
    print("可能原因:")
    print("  1. 微信未登录")
    print("  2. 好友备注名不正确（注意区分大小写）")
    print("  3. 该好友没有发布任何朋友圈")
    print("  4. 朋友圈权限受限")
    print()
    print("建议:")
    print("  1. 确认微信已登录")
    print("  2. 手动打开微信，搜索该好友，确认备注名")
    print("  3. 手动进入该好友的朋友圈，确认可以查看")
