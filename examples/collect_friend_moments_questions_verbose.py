"""Collect historical moments with verbose progress output."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
from typing import Any

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin import Moments
from pyweixin.moments_question_miner import (
    DEFAULT_QUESTION_KEYWORDS,
    QuestionFilter,
    extract_question_snippets,
    match_question_post,
)


def _safe_name(text: str) -> str:
    bad = '<>:"/\\|?*'
    out = text
    for ch in bad:
        out = out.replace(ch, "_")
    return out.strip() or "friend"


def _read_utf8(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def _write_markdown(path: str, friend: str, all_posts: list[dict], matched: list[dict], flt: QuestionFilter) -> None:
    lines: list[str] = []
    lines.append(f"# 朋友圈题目采集报告 - {friend}")
    lines.append("")
    lines.append(f"- 总采集条数: {len(all_posts)}")
    lines.append(f"- 题目候选条数: {len(matched)}")
    lines.append(f"- include关键词: {flt.include_keywords}")
    lines.append(f"- exclude关键词: {flt.exclude_keywords}")
    lines.append(f"- regex规则: {flt.regex_patterns}")
    lines.append("")
    for idx, item in enumerate(matched, start=1):
        lines.append(f"## {idx}. {item.get('发布时间','')}")
        lines.append("")
        lines.append(f"- 索引: {item.get('index')}")
        lines.append(f"- 图片数量: {item.get('图片数量',0)}")
        lines.append(f"- 视频数量: {item.get('视频数量',0)}")
        lines.append(f"- 详情目录: {item.get('detail_folder','')}")
        lines.append(f"- 内容文件: {item.get('content_file','')}")
        lines.append(f"- 截图文件: {item.get('screenshot_file','')}")
        lines.append("- 题目片段:")
        snippets = item.get("question_snippets", [])
        if snippets:
            for snippet in snippets:
                lines.append(f"  - {snippet}")
        else:
            lines.append("  - (无)")
        lines.append("- 原始内容:")
        lines.append("```text")
        lines.append(item.get("内容", ""))
        lines.append("```")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect one friend's moments with verbose progress.")
    parser.add_argument("--friend", required=True, help="好友备注名")
    parser.add_argument("--number", type=int, default=200, help="抓取条数上限(默认200)")
    parser.add_argument("--all", action="store_true", help="抓取当前可访问的全部朋友圈")
    parser.add_argument(
        "--output",
        default="dataset",
        help="输出目录根路径，默认 dataset",
    )
    parser.add_argument(
        "--include",
        nargs="*",
        default=None,
        help="题目包含关键词，可传多个",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="排除关键词，可传多个",
    )
    parser.add_argument(
        "--regex",
        nargs="*",
        default=[],
        help="正则匹配规则，可传多个",
    )
    parser.add_argument("--save-detail", action="store_true", default=True, help="保存每条朋友圈详情")
    parser.add_argument("--is-maximize", action="store_true", help="微信窗口全屏")
    parser.add_argument("--keep-weixin", action="store_true", help="任务结束后不关闭微信")
    args = parser.parse_args()

    include = args.include if args.include is not None else list(DEFAULT_QUESTION_KEYWORDS)
    flt = QuestionFilter(
        include_keywords=include,
        exclude_keywords=args.exclude or [],
        regex_patterns=args.regex or [],
    )

    ts = time.strftime("%Y%m%d_%H%M%S")
    friend_name = _safe_name(args.friend)
    output_root = os.path.join(args.output, f"moments_questions_{friend_name}_{ts}")
    os.makedirs(output_root, exist_ok=True)

    print("=" * 60)
    print(f"朋友圈题目采集（详细模式）")
    print("=" * 60)
    print(f"好友: {args.friend}")
    print(f"模式: {'全部' if args.all else f'最近{args.number}条'}")
    print(f"输出: {output_root}")
    print(f"筛选: include={include}")
    print(f"排除: exclude={args.exclude}")
    print("=" * 60)
    print()

    print("[1/3] 正在启动微信自动化...")
    print("  提示: 请不要操作电脑，观察微信窗口是否自动打开朋友圈")
    print("  预计耗时: 5-15分钟（取决于朋友圈数量）")
    print()

    start_time = time.time()
    try:
        if args.all:
            print("  调用: Moments.dump_all_friend_moments()")
            posts = Moments.dump_all_friend_moments(
                friend=args.friend,
                save_detail=args.save_detail,
                target_folder=output_root,
                is_maximize=args.is_maximize,
                close_weixin=not args.keep_weixin,
            )
        else:
            print(f"  调用: Moments.dump_friend_moments(number={args.number})")
            posts = Moments.dump_friend_moments(
                friend=args.friend,
                number=max(1, args.number),
                save_detail=args.save_detail,
                target_folder=output_root,
                is_maximize=args.is_maximize,
                close_weixin=not args.keep_weixin,
            )
    except Exception as exc:
        print(f"\n✗ 错误: {exc}")
        print("\n可能原因:")
        print("  1. 微信未登录")
        print("  2. 好友备注名不正确")
        print("  3. 朋友圈权限受限")
        print("\n请检查后重试。")
        return

    elapsed = time.time() - start_time
    print(f"\n[2/3] 抓取完成！共 {len(posts)} 条，耗时 {elapsed:.1f}秒")
    print("  正在筛选题目候选...")

    friend_folder = os.path.join(output_root, args.friend)
    all_rows: list[dict[str, Any]] = []
    matched_rows: list[dict[str, Any]] = []
    for idx, post in enumerate(posts):
        detail_folder = os.path.join(friend_folder, str(idx))
        content_file = os.path.join(detail_folder, "内容.txt")
        screenshot_file = os.path.join(detail_folder, "内容截图.png")
        text = _read_utf8(content_file) or str(post.get("内容", ""))
        snippets = extract_question_snippets(text)
        row = {
            "index": idx,
            "好友": args.friend,
            "发布时间": post.get("发布时间", ""),
            "内容": text,
            "图片数量": post.get("图片数量", 0),
            "视频数量": post.get("视频数量", 0),
            "question_snippets": snippets,
            "detail_folder": detail_folder if os.path.isdir(detail_folder) else "",
            "content_file": content_file if os.path.isfile(content_file) else "",
            "screenshot_file": screenshot_file if os.path.isfile(screenshot_file) else "",
        }
        all_rows.append(row)
        if match_question_post(text, flt):
            matched_rows.append(row)
            print(f"  ✓ 匹配: #{idx} {post.get('发布时间', '')} - {text[:30]}...")

    all_json = os.path.join(output_root, "all_posts.json")
    matched_json = os.path.join(output_root, "question_candidates.json")
    report_md = os.path.join(output_root, "question_candidates.md")
    _write_json(all_json, all_rows)
    _write_json(matched_json, matched_rows)
    _write_markdown(report_md, args.friend, all_rows, matched_rows, flt)

    print(f"\n[3/3] 导出完成！")
    print("=" * 60)
    print(f"✓ 总采集: {len(all_rows)} 条")
    print(f"✓ 题目候选: {len(matched_rows)} 条")
    print(f"✓ 总耗时: {time.time() - start_time:.1f}秒")
    print()
    print("输出文件:")
    print(f"  - 全部帖子: {all_json}")
    print(f"  - 题目候选: {matched_json}")
    print(f"  - 可读报告: {report_md}")
    print("=" * 60)
    print()
    print("下一步:")
    print(f"  1. 查看报告: notepad {report_md}")
    print("  2. 分析题型规律")
    print("  3. 补充模板到 config/rush_event.json")


if __name__ == "__main__":
    main()
