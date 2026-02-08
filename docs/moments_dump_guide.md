# 好友朋友圈保存功能说明（当前实现）

## 1. 功能范围

当前仓库中“保存好友朋友圈”的能力由两层组成：

1. 底层 API：`Moments.dump_friend_moments(...)`
2. 上层脚本：
`examples/collect_friend_moments_questions.py`
`examples/collect_friend_moments_questions_verbose.py`

底层 API 负责抓取与可选详情保存；上层脚本负责关键词/正则筛选和结果导出。

---

## 2. 底层 API（真实可用参数）

函数签名：

```python
Moments.dump_friend_moments(
    friend: str,
    number: int,
    save_detail: bool = False,
    target_folder: str = None,
    is_maximize: bool = None,
    close_weixin: bool = None,
    detail_content_filter: Callable[[str], bool] = None,
    debug: bool = False,
    search_pages: int = None,
) -> list[dict]
```

参数说明：

1. `friend`：好友备注名（用于打开该好友朋友圈）。
2. `number`：目标抓取条数上限（去重后计数）。
3. `save_detail`：是否保存详情文件（内容截图、内容文本、图片）。
4. `target_folder`：详情保存根目录。
5. `detail_content_filter`：详情保存过滤函数，返回 `True` 才保存详情目录；不影响结构化 `posts` 结果。
6. `debug`：输出 `DUMP-DEBUG` 调试日志。
7. `search_pages`：打开好友时会话列表滚动查找页数；`0` 表示顶部搜索（更快）。

返回结构：

```json
[
  {"内容":"...", "图片数量":0, "视频数量":0, "发布时间":"..."}
]
```

---

## 3. 当前实现行为（关键点）

### 3.1 可点击项过滤

抓取循环里会先拿到列表项，再过滤成“当前视口内可点击”的项后才尝试点开详情。  
目的是避免读取到了文本但该项实际不在可点击区域，导致反复点不开。

### 3.2 去重策略

1. 列表项 key：`class_name + 文本(去空白后)` 的哈希，减少坐标抖动引起的重复点击。
2. 内容去重：`sha1(content + post_time + photo_num + video_num)`，避免同一条被重复计入 `posts`。

### 3.3 详情打开失败的降级

如果某条内容连续多次无法打开详情：

1. 会把该条标记为已处理，避免卡死重试。
2. 用列表快照解析出的 `quick_content` 作为降级结果写入 `posts`（无详情目录）。
3. 调试日志会出现：
`fallback append quick content after repeated detail-open failures`

### 3.4 滚动策略

1. 默认小步下滚：`{DOWN}`。
2. 连续无变化时自动改用 `{PGDN}` 增大滚动幅度。
3. 无进展会触发保护退出，避免无限循环。

---

## 4. 推荐脚本用法

## 4.1 标准模式（推荐日常）

```powershell
python examples/collect_friend_moments_questions.py --friend 七人格 --number 200 --include 抢答 问题 题目 --save-matched-only --output dataset
```

## 4.2 详细调试模式（排障）

```powershell
python examples/collect_friend_moments_questions_verbose.py --friend 七人格 --number 50 --include 抢答 问题 题目 --save-matched-only --search-pages 0 --debug --output dataset
```

## 4.3 全量大上限模式

```powershell
python examples/collect_friend_moments_questions.py --friend 七人格 --all --all-number 5000 --include 抢答 问题 题目 --save-matched-only --output dataset
```

---

## 5. 输出目录结构

以 `--output dataset` 为例：

```text
dataset/
  moments_questions_<好友>_<时间戳>/
    all_posts.json
    question_candidates.json
    question_candidates.md
    <好友>/
      0/
        内容.txt
        内容截图.png
        0.png
        1.png
      1/
      ...
```

说明：

1. `all_posts.json`：本轮抓取到的结构化结果（包含未命中关键词的帖子）。
2. `question_candidates.json`：关键词/正则命中的候选结果。
3. `question_candidates.md`：可读报告。
4. 某些条目若走了“详情失败降级”，可能没有对应数字目录，但仍会出现在 `all_posts.json`。

---

## 6. 已知限制

1. 微信 UI 会有动态虚拟化，列表“可读”不等于“可点击”，这是详情失败的核心来源之一。
2. 某些超长文本、折叠状态或窗口遮挡场景，详情页定位会失败，当前策略是降级保留文本继续抓取。
3. `detail_content_filter` 只影响“是否保存详情目录”，不影响 `posts` 计数和结构化导出。
4. 自动化执行期间建议不要手动操作微信窗口，否则会增大定位失败概率。

---

## 7. 建议排障步骤

1. 先跑 `verbose + --debug`，看是否出现大量 `process failed key=...`。
2. 若失败集中在某些条目，关注是否随后的 `fallback append quick content...` 已生效。
3. 观察日志中的 `all=xx visible=yy`：
`visible` 明显偏小或频繁为 `0`，一般是视口可点击性问题，而非解析问题。
4. 优先保持 `--search-pages 0`，减少打开路径上的额外滚动不确定性。

