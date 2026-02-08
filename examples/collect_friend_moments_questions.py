"""Collect historical moments from one friend and mine question-like posts."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import sys
import time
from typing import Any

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.moments_ext import dump_friend_moments
from pyweixin.moments_question_miner import (
    QuestionFilter,
    extract_question_snippets,
    match_question_post,
)

DEFAULT_SAVE_KEYWORDS = ["题目", "抢答", "问题"]
DEFAULT_ALL_NUMBER = 5000


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


def _validate_regex_patterns(patterns: list[str]) -> None:
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {pattern!r}, error: {exc}") from exc


def _resolve_fetch_number(*, number: int, fetch_all: bool, all_number: int) -> int:
    if fetch_all:
        return max(1, all_number)
    return max(1, number)


def _resolve_friend_folder(output_root: str, friend: str) -> str:
    candidates = [
        os.path.join(output_root, friend),
        os.path.join(output_root, _safe_name(friend)),
    ]
    for path in candidates:
        if os.path.isdir(path):
            return path
    return candidates[0]


def _cleanup_unmatched_detail_folders(friend_folder: str, matched_indices: set[int]) -> tuple[int, int]:
    if not os.path.isdir(friend_folder):
        return 0, 0
    kept = 0
    removed = 0
    for name in os.listdir(friend_folder):
        path = os.path.join(friend_folder, name)
        if not os.path.isdir(path) or not name.isdigit():
            continue
        idx = int(name)
        if idx in matched_indices:
            kept += 1
            continue
        try:
            shutil.rmtree(path)
            removed += 1
        except OSError:
            pass
    return kept, removed


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect one friend's moments and mine question posts.")
    parser.add_argument("--friend", required=True, help="好友备注名")
    parser.add_argument("--number", type=int, default=200, help="抓取条数上限(默认200)")
    parser.add_argument("--all", action="store_true", help="抓取当前可访问的全部朋友圈")
    parser.add_argument(
        "--all-number",
        type=int,
        default=DEFAULT_ALL_NUMBER,
        help="--all 模式下的最大抓取条数上限(默认5000)",
    )
    parser.add_argument(
        "--output",
        default="dataset",
        help="输出目录根路径，默认 dataset",
    )
    parser.add_argument(
        "--include",
        nargs="*",
        default=None,
        help="题目包含关键词，可传多个，例如 --include 题目 抢答 问题（默认：题目 抢答 问题）",
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
    parser.add_argument(
        "--save-detail",
        dest="save_detail",
        action="store_true",
        default=True,
        help="保存每条朋友圈详情(默认开启)",
    )
    parser.add_argument(
        "--no-save-detail",
        dest="save_detail",
        action="store_false",
        help="不保存详情文件，只输出结构化结果",
    )
    parser.add_argument(
        "--save-matched-only",
        dest="save_matched_only",
        action="store_true",
        default=True,
        help="仅保留命中关键词/正则的详情目录(默认开启)",
    )
    parser.add_argument(
        "--save-all-detail",
        dest="save_matched_only",
        action="store_false",
        help="保留抓取到的全部详情目录，不做未命中清理",
    )
    parser.add_argument("--debug", action="store_true", help="打印底层采集详细调试日志")
    parser.add_argument(
        "--search-pages",
        type=int,
        default=0,
        help="打开聊天前会话列表滚动查找页数。0=直接顶部搜索(更快)，默认0",
    )
    parser.add_argument("--is-maximize", action="store_true", help="微信窗口全屏")
    parser.add_argument("--keep-weixin", action="store_true", help="任务结束后不关闭微信")
    args = parser.parse_args()

    include = args.include if args.include is not None else list(DEFAULT_SAVE_KEYWORDS)
    try:
        _validate_regex_patterns(args.regex or [])
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return
    flt = QuestionFilter(
        include_keywords=include,
        exclude_keywords=args.exclude or [],
        regex_patterns=args.regex or [],
    )
    fetch_number = _resolve_fetch_number(number=args.number, fetch_all=args.all, all_number=args.all_number)

    ts = time.strftime("%Y%m%d_%H%M%S")
    friend_name = _safe_name(args.friend)
    output_root = os.path.join(args.output, f"moments_questions_{friend_name}_{ts}")
    os.makedirs(output_root, exist_ok=True)

    mode_name = "全部(大上限模式)" if args.all else f"最近{fetch_number}条"
    print(f"[1/3] 开始抓取朋友圈: friend={args.friend} mode={mode_name} output={output_root}")
    try:
        detail_filter = (lambda text: match_question_post(text, flt)) if (args.save_detail and args.save_matched_only) else None
        posts = dump_friend_moments(
            friend=args.friend,
            number=fetch_number,
            save_detail=args.save_detail,
            target_folder=output_root,
            is_maximize=args.is_maximize,
            close_weixin=not args.keep_weixin,
            detail_content_filter=detail_filter,
            debug=args.debug,
            search_pages=max(0, args.search_pages),
        )
    except Exception as exc:
        print(f"\n[ERROR] 抓取失败: {exc}")
        print("建议检查: 微信是否登录 / 好友备注是否正确 / 该好友朋友圈权限")
        return

    print(f"[2/3] 抓取完成，共 {len(posts)} 条，开始筛选题目候选")
    friend_folder = _resolve_friend_folder(output_root, args.friend)
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

    if args.save_detail and args.save_matched_only:
        matched_indices = {
            int(row["index"])
            for row in matched_rows
            if isinstance(row.get("index"), int)
        }
        kept, removed = _cleanup_unmatched_detail_folders(friend_folder, matched_indices)
        print(f"[INFO] detail folders kept={kept}, removed_unmatched={removed}")

    all_json = os.path.join(output_root, "all_posts.json")
    matched_json = os.path.join(output_root, "question_candidates.json")
    report_md = os.path.join(output_root, "question_candidates.md")
    _write_json(all_json, all_rows)
    _write_json(matched_json, matched_rows)
    _write_markdown(report_md, args.friend, all_rows, matched_rows, flt)

    print("[3/3] 导出完成")
    print(f"- all posts: {all_json}")
    print(f"- question candidates: {matched_json}")
    print(f"- report: {report_md}")


if __name__ == "__main__":
    main()
