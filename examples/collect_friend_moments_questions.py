"""Collect historical moments from one friend and mine question-like posts."""

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
    QuestionFilter,
    extract_question_snippets,
    match_question_post,
)

DEFAULT_SAVE_KEYWORDS = ["题目", "抢答", "问题"]


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

def _contains_any_keyword(text: str, keywords: list[str]) -> bool:
    if not text:
        return False
    return any(kw and kw in text for kw in keywords)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect one friend's moments and mine question posts.")
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
    parser.add_argument("--save-detail", action="store_true", default=True, help="保存每条朋友圈详情")
    parser.add_argument("--is-maximize", action="store_true", help="微信窗口全屏")
    parser.add_argument("--keep-weixin", action="store_true", help="任务结束后不关闭微信")
    args = parser.parse_args()

    include = args.include if args.include is not None else list(DEFAULT_SAVE_KEYWORDS)
    flt = QuestionFilter(
        include_keywords=include,
        exclude_keywords=args.exclude or [],
        regex_patterns=args.regex or [],
    )

    ts = time.strftime("%Y%m%d_%H%M%S")
    friend_name = _safe_name(args.friend)
    output_root = os.path.join(args.output, f"moments_questions_{friend_name}_{ts}")
    os.makedirs(output_root, exist_ok=True)

    print(f"[1/3] 开始抓取朋友圈: friend={args.friend} output={output_root}")
    detail_filter = lambda text: _contains_any_keyword(text, include)
    if args.all:
        posts = Moments.dump_all_friend_moments(
            friend=args.friend,
            save_detail=args.save_detail,
            target_folder=output_root,
            is_maximize=args.is_maximize,
            close_weixin=not args.keep_weixin,
            detail_content_filter=detail_filter,
        )
    else:
        posts = Moments.dump_friend_moments(
            friend=args.friend,
            number=max(1, args.number),
            save_detail=args.save_detail,
            target_folder=output_root,
            is_maximize=args.is_maximize,
            close_weixin=not args.keep_weixin,
            detail_content_filter=detail_filter,
        )

    print(f"[2/3] 抓取完成，共 {len(posts)} 条，开始筛选题目候选")
    friend_folder = os.path.join(output_root, _safe_name(args.friend))
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
