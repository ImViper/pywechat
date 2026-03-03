"""
Viper Moments Extension — 朋友圈自动评论与增强功能。
不修改 upstream 代码，只导入其公共 API。
"""
import os
import re
import time
import json
import hashlib
import threading
from datetime import datetime, timedelta
import pyautogui
import win32gui
import win32con
from typing import Callable, Literal
from pywinauto import WindowSpecification
from pywinauto.controls.uia_controls import ListItemWrapper, ListViewWrapper

# --- 从 upstream 导入（公共 API） ---
from .WeChatTools import Tools, Navigator, mouse, desktop
from .WeChatTools import Buttons, Edits, Lists, Windows
from .WinSettings import SystemSettings
from .Config import GlobalConfig
from .Errors import NotFolderError
from .Uielements import MenuItems as _MenuItemsCls
from .utils import Regex_Patterns

# 实例化本模块需要但 WeChatTools 未导出的 UI 元素
_regex_patterns = Regex_Patterns()
MenuItems = _MenuItemsCls()

# ---------------------------------------------------------------------------
# 3a. SNS 偏移量配置
# ---------------------------------------------------------------------------
_SNS_ELLIPSIS_X_OFFSET = 44
_SNS_ELLIPSIS_Y_OFFSET = 15
_SNS_SEND_LIST_X_OFFSET = 70
_SNS_SEND_LIST_Y_OFFSET = 42
_SNS_SEND_DETAIL_X_OFFSET = 70
_SNS_SEND_DETAIL_Y_OFFSET = 42
_SNS_CLICK_RETRY = 2
_SNS_OFFSET_CONFIG_ENV = "PYWEIXIN_SNS_OFFSET_FILE"


def _apply_sns_click_offsets(
    ellipsis_x: int | None = None,
    ellipsis_y: int | None = None,
    send_list_x: int | None = None,
    send_list_y: int | None = None,
    send_detail_x: int | None = None,
    send_detail_y: int | None = None,
    click_retry: int | None = None,
):
    """Override default SNS click offsets at runtime."""
    global _SNS_ELLIPSIS_X_OFFSET, _SNS_ELLIPSIS_Y_OFFSET
    global _SNS_SEND_LIST_X_OFFSET, _SNS_SEND_LIST_Y_OFFSET
    global _SNS_SEND_DETAIL_X_OFFSET, _SNS_SEND_DETAIL_Y_OFFSET
    global _SNS_CLICK_RETRY

    if ellipsis_x is not None:
        _SNS_ELLIPSIS_X_OFFSET = int(ellipsis_x)
    if ellipsis_y is not None:
        _SNS_ELLIPSIS_Y_OFFSET = int(ellipsis_y)
    if send_list_x is not None:
        _SNS_SEND_LIST_X_OFFSET = int(send_list_x)
    if send_list_y is not None:
        _SNS_SEND_LIST_Y_OFFSET = int(send_list_y)
    if send_detail_x is not None:
        _SNS_SEND_DETAIL_X_OFFSET = int(send_detail_x)
    if send_detail_y is not None:
        _SNS_SEND_DETAIL_Y_OFFSET = int(send_detail_y)
    if click_retry is not None:
        _SNS_CLICK_RETRY = max(int(click_retry), 1)


def _load_sns_click_offsets():
    """Load SNS click offsets from JSON config file (optional)."""
    config_path = os.environ.get(_SNS_OFFSET_CONFIG_ENV)
    if not config_path or not os.path.isfile(config_path):
        return
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        _apply_sns_click_offsets(
            ellipsis_x=data.get('ellipsis_x'),
            ellipsis_y=data.get('ellipsis_y'),
            send_list_x=data.get('send_list_x'),
            send_list_y=data.get('send_list_y'),
            send_detail_x=data.get('send_detail_x'),
            send_detail_y=data.get('send_detail_y'),
            click_retry=data.get('click_retry'),
        )
    except Exception:
        pass


# 模块加载时自动执行
_load_sns_click_offsets()

# ---------------------------------------------------------------------------
# 3b. UI 元素字典（本模块私有定义）
# ---------------------------------------------------------------------------
COMMENT_BUTTON = {'title': '评论', 'control_type': 'Button'}
LIKE_BUTTON = {'title': '赞', 'control_type': 'Button'}
SNS_COMMENT_EDIT = {'title': '', 'control_type': 'Edit', 'class_name': 'mmui::XValidatorTextEdit'}

# ---------------------------------------------------------------------------
# 3c. 绿色像素检测
# ---------------------------------------------------------------------------

def _is_green_pixel(r: int, g: int, b: int) -> bool:
    """Heuristic for WeChat send button green."""
    if g < 80:
        return False
    if (g - r) < 18 or (g - b) < 8:
        return False
    if g < int(r * 1.18):
        return False
    if g < int(b * 1.10):
        return False
    return True


def _find_green_button_center(region: tuple[int, int, int, int]) -> tuple[int, int] | None:
    """Find center point of the largest green-ish area in a region."""
    try:
        screenshot = pyautogui.screenshot(region=region).convert('RGB')
    except Exception:
        return None
    width, height = screenshot.size
    if width <= 0 or height <= 0:
        return None
    pixels = screenshot.load()
    min_x, min_y = width, height
    max_x, max_y = -1, -1
    hit_count = 0
    for y in range(0, height, 2):
        for x in range(0, width, 2):
            r, g, b = pixels[x, y]
            if _is_green_pixel(r, g, b):
                hit_count += 1
                if x < min_x:
                    min_x = x
                if y < min_y:
                    min_y = y
                if x > max_x:
                    max_x = x
                if y > max_y:
                    max_y = y
    if hit_count < 18 or max_x < 0 or max_y < 0:
        return None
    if (max_x - min_x) < 10 or (max_y - min_y) < 6:
        return None
    center_x = region[0] + (min_x + max_x) // 2
    center_y = region[1] + (min_y + max_y) // 2
    return center_x, center_y


def _click_send_button(anchor_rect, x_offset: int = 70, y_offset: int = 42) -> bool:
    """Click send button using green-pixel detection with coordinate fallback."""
    fallback_coords = (anchor_rect.right - x_offset, anchor_rect.bottom - y_offset)
    regions = [
        (max(fallback_coords[0] - 80, 0), max(fallback_coords[1] - 40, 0), 160, 80),
        (max(anchor_rect.right - (x_offset + 140), 0), max(anchor_rect.bottom - (y_offset + 80), 0), 260, 150),
    ]
    for region in regions:
        green_center = _find_green_button_center(region)
        if green_center is not None:
            mouse.click(coords=green_center)
            return True
    mouse.click(coords=fallback_coords)
    return False


def _is_valid_anchor_rect(rect) -> bool:
    """Validate anchor rectangle before coordinate-based send click."""
    try:
        left = int(rect.left)
        top = int(rect.top)
        right = int(rect.right)
        bottom = int(rect.bottom)
    except Exception:
        return False
    w = right - left
    h = bottom - top
    if w < 30 or h < 20:
        return False
    if right <= 0 or bottom <= 0:
        return False
    if left == 0 and top == 0 and right == 0 and bottom == 0:
        return False
    return True


# ---------------------------------------------------------------------------
# 3d. ListItem 辅助函数
# ---------------------------------------------------------------------------

def _listitem_signature(listitem: ListItemWrapper):
    """Build a multi-field signature for list item identity."""
    runtime_id = None
    class_name = ''
    text = ''
    rect_key = None
    try:
        _runtime_id = getattr(listitem.element_info, 'runtime_id', None)
        if _runtime_id is not None:
            runtime_id = tuple(_runtime_id)
    except Exception:
        runtime_id = None
    try:
        class_name = listitem.class_name()
    except Exception:
        class_name = ''
    try:
        text = listitem.window_text()
    except Exception:
        text = ''
    try:
        r = listitem.rectangle()
        rect_key = (r.left, r.top, r.right, r.bottom)
    except Exception:
        rect_key = None
    return (runtime_id, class_name, text, rect_key)


def _find_listitem_index(items: list, listitem: ListItemWrapper):
    """Find list item index using equality then signature fallback."""
    try:
        target_sig = _listitem_signature(listitem)
    except Exception:
        target_sig = None
    for i, item in enumerate(items):
        if item == listitem:
            return i
    if target_sig is not None:
        for i, item in enumerate(items):
            try:
                if _listitem_signature(item) == target_sig:
                    return i
            except Exception:
                continue
    return None


def _is_clickable_in_viewport(listitem: ListItemWrapper, moments_list) -> bool:
    """Check if a list item is visible and clickable within the viewport."""
    try:
        if hasattr(listitem, 'is_visible') and (not listitem.is_visible()):
            return False
    except Exception:
        pass
    try:
        item_rect = listitem.rectangle()
        list_rect = moments_list.rectangle()
        visible_w = min(item_rect.right, list_rect.right) - max(item_rect.left, list_rect.left)
        visible_h = min(item_rect.bottom, list_rect.bottom) - max(item_rect.top, list_rect.top)
        if visible_w < 40 or visible_h < 30:
            return False
        center = item_rect.mid_point()
        if center.x < list_rect.left + 8 or center.x > list_rect.right - 8:
            return False
        if center.y < list_rect.top + 8 or center.y > list_rect.bottom - 8:
            return False
    except Exception:
        return False
    return True


def _click_item_in_viewport(listitem: ListItemWrapper, moments_list):
    """Click a list item within the visible viewport bounds."""
    item_rect = listitem.rectangle()
    list_rect = moments_list.rectangle()
    x = min(max(item_rect.mid_point().x, list_rect.left + 16), list_rect.right - 16)
    y = min(max(item_rect.mid_point().y, list_rect.top + 16), list_rect.bottom - 16)
    mouse.click(coords=(x, y))


def _build_item_key(listitem: ListItemWrapper) -> tuple:
    """Build a stable hash key for a list item (no coordinates)."""
    text = ''
    class_name = ''
    try:
        text = listitem.window_text()
    except Exception:
        text = ''
    try:
        class_name = listitem.class_name()
    except Exception:
        class_name = ''
    compact_text = re.sub(r'\s+', '', text)
    if len(compact_text) > 500:
        compact_text = compact_text[:500]
    digest = hashlib.sha1()
    digest.update(class_name.encode('utf-8', errors='ignore'))
    digest.update(compact_text.encode('utf-8', errors='ignore'))
    return ('item', digest.hexdigest())


def _parse_relative_post_age_minutes(post_time: str):
    """Parse relative publish time text to age in minutes.

    Returns:
      - int minutes for relative timestamps (e.g. 3分钟前 / 2小时前 / 昨天 / 5天前)
      - None when format is unknown or empty.
    """
    if not post_time:
        return None
    s = str(post_time).strip()
    if not s:
        return None
    if s == '刚刚':
        return 0
    m = re.match(r'^(\d+)分钟前$', s)
    if m:
        return int(m.group(1))
    m = re.match(r'^(\d+)小时前$', s)
    if m:
        return int(m.group(1)) * 60
    m = re.match(r'^(\d+)天前$', s)
    if m:
        return int(m.group(1)) * 24 * 60
    if s == '昨天':
        return 24 * 60
    return None


def _normalize_post_time_for_fingerprint(post_time: str) -> str:
    """Normalize publish time to reduce fingerprint churn on relative timestamps."""
    age_minutes = _parse_relative_post_age_minutes(post_time)
    if age_minutes is not None:
        # Relative timestamps drift over time (e.g. 1分钟前 -> 2分钟前).
        # For dedup fingerprints we collapse them to a stable token.
        return '__RELATIVE_TIME__'
    return (post_time or '')


def _build_post_fingerprint(content: str, post_time: str, photo_num: int, video_num: int, item_key) -> str:
    """Build fingerprint for post deduplication."""
    hasher = hashlib.sha1()
    hasher.update((content or '').encode('utf-8', errors='ignore'))
    normalized_post_time = _normalize_post_time_for_fingerprint(post_time)
    hasher.update(normalized_post_time.encode('utf-8', errors='ignore'))
    hasher.update(str(photo_num).encode('utf-8'))
    hasher.update(str(video_num).encode('utf-8'))
    if not (content or normalized_post_time):
        hasher.update(str(item_key).encode('utf-8', errors='ignore'))
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# 3e. Navigator 增强 wrapper
# ---------------------------------------------------------------------------

def open_friend_moments_robust(friend: str, retries: int = 3, **kwargs) -> WindowSpecification:
    """增强版：在 upstream Navigator.open_friend_moments 基础上加重试和 fallback。"""
    last_error = None
    for attempt in range(retries):
        try:
            return Navigator.open_friend_moments(friend=friend, **kwargs)
        except Exception as e:
            last_error = e
            if attempt == retries - 1:
                raise
            time.sleep(0.3)
    raise last_error


def open_friend_profile_robust(friend: str, retries: int = 3, **kwargs):
    """增强版：profile 面板加载重试。"""
    last_error = None
    for attempt in range(retries):
        try:
            return Navigator.open_friend_profile(friend=friend, **kwargs)
        except Exception as e:
            last_error = e
            if attempt == retries - 1:
                raise
            time.sleep(0.3)
    raise last_error


# ---------------------------------------------------------------------------
# 3f. 评论流程核心
# ---------------------------------------------------------------------------

def wait_comment_editor_state(moments_window, opened: bool, timeout: float = 1.0, poll: float = 0.08) -> bool:
    """Wait until comment editor appears/disappears."""
    deadline = time.time() + max(timeout, 0.0)
    while True:
        exists = False
        try:
            comment_edit = moments_window.child_window(**SNS_COMMENT_EDIT)
            exists = comment_edit.exists(timeout=0.05)
        except Exception:
            exists = False
        if exists == opened:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(max(poll, 0.02))


def open_comment_editor(moments_window, content_item, use_offset_fix: bool = False, pre_move_coords: tuple = None) -> bool:
    """Click ellipsis and open comment input."""
    print(f'[debug:open_editor] start, pre_move_coords={pre_move_coords}, use_offset_fix={use_offset_fix}')
    if wait_comment_editor_state(moments_window, opened=True, timeout=0.05, poll=0.02):
        print('[debug:open_editor] editor already open')
        return True
    comment_button = moments_window.child_window(**COMMENT_BUTTON)
    for attempt in range(_SNS_CLICK_RETRY):
        print(f'[debug:open_editor] attempt #{attempt + 1}/{_SNS_CLICK_RETRY}')
        if pre_move_coords is not None:
            mouse.move(coords=pre_move_coords)
            print(f'[debug:open_editor] moved mouse to {pre_move_coords}')
        rect = content_item.rectangle()
        print(f'[debug:open_editor] item rect: L={rect.left} T={rect.top} R={rect.right} B={rect.bottom}')
        x_offset = _SNS_ELLIPSIS_X_OFFSET
        if use_offset_fix:
            win_rect = moments_window.rectangle()
            x_offset += (rect.left - win_rect.left)
        ellipsis_area = (rect.right - x_offset, rect.bottom - _SNS_ELLIPSIS_Y_OFFSET)
        print(f'[debug:open_editor] clicking ellipsis at {ellipsis_area}')
        mouse.click(coords=ellipsis_area)
        time.sleep(0.08)
        btn_exists = comment_button.exists(timeout=0.3)
        print(f'[debug:open_editor] comment_button.exists={btn_exists}')
        if btn_exists:
            try:
                comment_button.click_input()
                time.sleep(0.05)
                print('[debug:open_editor] clicked comment button, returning True')
                return True
            except Exception as e:
                print(f'[debug:open_editor] click_input failed: {e}')
        pyautogui.press('esc')
        time.sleep(0.1)
    print('[debug:open_editor] all attempts failed, returning False')
    return False


def paste_and_send_comment(moments_window, text: str, anchor_mode: str = 'list', anchor_source=None, clear_first: bool = True, skip_editor_check: bool = False) -> bool:
    """Paste text and verify send success by editor close state."""
    print(f'[debug:paste_send] start, text={text!r}, anchor_mode={anchor_mode}, clear_first={clear_first}')
    if skip_editor_check:
        print('[debug:paste_send] skip_editor_check=True, editor assumed open')
    else:
        editor_detected = wait_comment_editor_state(moments_window, opened=True, timeout=0.2, poll=0.05)
        if not editor_detected:
            print('[debug:paste_send] editor element not detected, but proceeding anyway (editor may be open)')
    if clear_first:
        pyautogui.hotkey('ctrl', 'a')
        pyautogui.press('backspace')
    SystemSettings.copy_text_to_windowsclipboard(text=text)
    pyautogui.hotkey('ctrl', 'v')
    time.sleep(0.03)
    print('[debug:paste_send] pasted text')
    clicked_by_anchor = False
    if anchor_source is not None:
        try:
            cr = anchor_source.rectangle()
            print(f'[debug:paste_send] anchor rect: L={cr.left} T={cr.top} R={cr.right} B={cr.bottom}')
            if _is_valid_anchor_rect(cr):
                if anchor_mode == 'list':
                    _click_send_button(cr, x_offset=_SNS_SEND_LIST_X_OFFSET, y_offset=_SNS_SEND_LIST_Y_OFFSET)
                else:
                    _click_send_button(cr, x_offset=_SNS_SEND_DETAIL_X_OFFSET, y_offset=_SNS_SEND_DETAIL_Y_OFFSET)
                clicked_by_anchor = True
                print('[debug:paste_send] clicked send by anchor')
            else:
                print('[debug:paste_send] invalid anchor rect, send aborted (no enter fallback)')
        except Exception as e:
            clicked_by_anchor = False
            print(f'[debug:paste_send] anchor click failed: {e}')
    if not clicked_by_anchor:
        print('[debug:paste_send] anchor send unavailable, returning False (enter disabled)')
        return False
    closed = wait_comment_editor_state(moments_window, opened=False, timeout=0.4, poll=0.05)
    print(f'[debug:paste_send] editor closed after send={closed}')
    if closed:
        return True
    print('[debug:paste_send] returning False')
    return False


def comment_flow(moments_window, content_item, comments, anchor_mode: str = 'list',
                 anchor_source=None, use_offset_fix: bool = False,
                 pre_move_coords: tuple = None, clear_first: bool = True,
                 callback: Callable[[str], str] = None) -> bool:
    """Unified comment flow: open editor -> paste -> send."""
    if isinstance(comments, str):
        comments = [comments]
    sent_any = False
    for idx, text in enumerate(comments):
        text = str(text).strip()
        if not text:
            continue
        if callback is not None:
            text = callback(text)
            text = str(text).strip() if text is not None else ''
        if not text:
            continue
        opened = open_comment_editor(
            moments_window, content_item,
            use_offset_fix=use_offset_fix,
            pre_move_coords=pre_move_coords)
        if not opened:
            print(f'[comment] failed to open editor for comment #{idx + 1}, skip')
            continue
        posted = paste_and_send_comment(
            moments_window, text,
            anchor_mode=anchor_mode,
            anchor_source=anchor_source,
            clear_first=clear_first)
        if posted:
            sent_any = True
        else:
            print(f'[comment] failed to send comment #{idx + 1}')
        if idx < len(comments) - 1:
            time.sleep(0.2)
    return sent_any


# ---------------------------------------------------------------------------
# 3g. 增强版 dump/like 方法
# ---------------------------------------------------------------------------

def dump_friend_moments(
    friend: str,
    number: int,
    save_detail: bool = False,
    target_folder: str = None,
    is_maximize: bool = None,
    close_weixin: bool = None,
    detail_content_filter: Callable[[str], bool] = None,
    debug: bool = False,
    search_pages: int = None
) -> list[dict]:
    '''
    增强版：获取某个好友的微信朋友圈的一定数量的内容。
    带 fingerprint 去重、viewport 检测、debug 日志。
    '''
    def log_debug(message: str):
        if not debug:
            return
        try:
            now = time.strftime('%H:%M:%S')
        except Exception:
            now = ''
        prefix = f"[DUMP-DEBUG {now}] " if now else "[DUMP-DEBUG] "
        print(prefix + str(message))

    def save_media(sns_detail_list, photo_num: int, detail_folder: str, content: str):
        content_path = os.path.join(detail_folder, '内容.txt')
        capture_path = os.path.join(detail_folder, '内容截图.png')
        sns_detail_list.children(control_type='ListItem')[0].capture_as_image().save(capture_path)
        with open(content_path, 'w', encoding='utf-8') as f:
            f.write(content)
        if photo_num:
            rec = sns_detail_list.rectangle()
            right_click_position = rec.mid_point().x + 20, rec.mid_point().y + 25
            comment_detail = sns_detail_list.children(control_type='ListItem', title='')[1]
            rec = comment_detail.rectangle()
            x, y = rec.left + 120, rec.top - 80
            mouse.click(coords=(x, y))
            pyautogui.press('left', presses=photo_num, interval=0.15)
            for i in range(photo_num):
                sns_detail_list.right_click_input(coords=right_click_position)
                moments_window.child_window(**MenuItems.CopyMenuItem).click_input()
                path = os.path.join(detail_folder, f'{i}.png')
                time.sleep(0.5)
                SystemSettings.save_pasted_image(path)
                pyautogui.press('right', interval=0.05)
            pyautogui.press('esc')

    def resolve_sns_detail_list(retries: int = 6, wait: float = 0.12):
        last_error = None
        selectors = [
            Lists.SnsDetailList,
            {'control_type': 'List', 'auto_id': 'sns_detail_list'},
        ]
        for _ in range(retries):
            for selector in selectors:
                try:
                    ctrl = moments_window.child_window(**selector)
                    if ctrl.exists(timeout=0):
                        return ctrl
                except Exception as exc:
                    last_error = exc
            time.sleep(wait)
        if last_error is not None:
            raise last_error
        raise RuntimeError('cannot locate friend moment detail list')

    def parse_friend_post(listitem: ListItemWrapper):
        video_num = 0
        photo_num = 0
        text = listitem.window_text()
        text = text.replace(friend, '')
        post_time_match = sns_detail_pattern.search(text)
        post_time = post_time_match.group(0) if post_time_match is not None else ''
        if re.search(r'\s包含(\d+)张图片\s', text):
            photo_num = int(re.search(r'\s包含(\d+)张图片\s', text).group(1))
        if post_time and re.search(rf'\s视频\s{re.escape(post_time)}', text):
            video_num = 1
        if post_time:
            content = re.sub(rf'\s((包含\d+张图片\s|视频\s).*{re.escape(post_time)})\s', '', text)
        else:
            content = re.sub(r'\s(包含\d+张图片\s|视频\s?)\s*', ' ', text)
        content = content.strip()
        return content, photo_num, video_num, post_time

    if is_maximize is None:
        is_maximize = GlobalConfig.is_maximize
    if close_weixin is None:
        close_weixin = GlobalConfig.close_weixin
    if save_detail and target_folder is None:
        target_folder = os.path.join(os.getcwd(), f'dump_friend_moments朋友圈图片保存')
        print(f'未传入文件夹图片和内容将保存到{target_folder}内的 {friend} 文件夹下')
        os.makedirs(target_folder, exist_ok=True)
    if save_detail and (not os.path.exists(target_folder) or not os.path.isdir(target_folder)):
        raise NotFolderError
    if save_detail and target_folder is not None:
        friend_folder = os.path.join(target_folder, f'{friend}')
        os.makedirs(friend_folder, exist_ok=True)
    posts = []
    recorded_num = 0
    sns_detail_pattern = _regex_patterns.Snsdetail_Timestamp_pattern
    not_contents = ['mmui::AlbumBaseCell', 'mmui::AlbumTopCell']
    log_debug(
        f"start friend={friend} number={number} save_detail={save_detail} "
        f"has_filter={detail_content_filter is not None} search_pages={search_pages}"
    )
    moments_window = Navigator.open_friend_moments(
        friend=friend,
        search_pages=search_pages,
        is_maximize=is_maximize,
        close_weixin=close_weixin
    )
    backbutton = moments_window.child_window(**Buttons.BackButton)
    win32gui.SendMessage(moments_window.handle, win32con.WM_SYSCOMMAND, win32con.SC_MAXIMIZE, 0)
    moments_list = moments_window.child_window(**Lists.MomentsList)
    moments_list.type_keys('{HOME}')
    time.sleep(0.05)
    moments_list.type_keys('{PGDN}')
    moments_list.type_keys('{PGUP}')
    moments_list.type_keys('{HOME}')
    contents = [
        listitem for listitem in moments_list.children(control_type='ListItem')
        if listitem.class_name() not in not_contents and _is_clickable_in_viewport(listitem, moments_list)
    ]
    log_debug(f"initial visible content count={len(contents)}")
    if contents:
        unresolved_rounds = 0
        stagnant_scroll_rounds = 0
        no_pick_rounds = 0
        max_failures_per_item = 2
        processed_keys = set()
        item_failures = {}
        seen_post_fingerprints = set()
        loop_no = 0
        while True:
            loop_no += 1
            try:
                if not moments_list.exists(timeout=0.3):
                    log_debug("ERROR: moments_list control lost, attempting recovery")
                    try:
                        moments_list = moments_window.child_window(**Lists.MomentsList)
                        if not moments_list.exists(timeout=0.5):
                            log_debug("FATAL: cannot recover moments_list, exiting")
                            break
                        log_debug("moments_list recovered successfully")
                    except Exception as recovery_err:
                        log_debug(f"FATAL: recovery failed: {recovery_err}")
                        break
            except Exception:
                pass

            try:
                all_items = [
                    listitem for listitem in moments_list.children(control_type='ListItem')
                    if listitem.class_name() not in not_contents
                ]
            except Exception:
                all_items = []
            visible_items = [item for item in all_items if _is_clickable_in_viewport(item, moments_list)]
            log_debug(
                f"loop={loop_no} all={len(all_items)} visible={len(visible_items)} recorded={recorded_num} "
                f"processed={len(processed_keys)} unresolved={unresolved_rounds} stagnant={stagnant_scroll_rounds}"
            )
            if not visible_items:
                moments_list.type_keys('{DOWN}')
                stagnant_scroll_rounds += 1
                if stagnant_scroll_rounds >= 80:
                    log_debug("exit: no visible items after 80 down-scroll attempts")
                    break
                if recorded_num >= number:
                    log_debug("exit: reached target number while visible items empty")
                    break
                continue
            try:
                visible_items = sorted(visible_items, key=lambda li: li.rectangle().top)
            except Exception:
                pass
            visible_keys = [_build_item_key(item) for item in visible_items]
            unprocessed_pairs = [
                (key, item) for key, item in zip(visible_keys, visible_items)
                if key not in processed_keys
            ]
            if unprocessed_pairs:
                no_pick_rounds = 0
                current_key, current_item = unprocessed_pairs[0]
                opened_detail = False
                quick_content = ''
                quick_photo_num = 0
                quick_video_num = 0
                quick_post_time = ''
                quick_fingerprint = None
                try:
                    preview = current_item.window_text().replace('\n', ' ')[:80]
                except Exception:
                    preview = ''
                log_debug(f"pick key={current_key} preview={preview}")
                try:
                    quick_content, quick_photo_num, quick_video_num, quick_post_time = parse_friend_post(current_item)
                    quick_fingerprint = _build_post_fingerprint(
                        quick_content, quick_post_time, quick_photo_num, quick_video_num, current_key
                    )
                    log_debug(
                        f"quick_parse time={quick_post_time or '(none)'} photos={quick_photo_num} "
                        f"videos={quick_video_num} text_len={len(quick_content)}"
                    )
                    log_debug("open detail: click list item")
                    _click_item_in_viewport(current_item, moments_list)
                    time.sleep(0.12)
                    sns_detail_list = resolve_sns_detail_list()
                    detail_items = sns_detail_list.children(control_type='ListItem')
                    if not detail_items:
                        raise RuntimeError('friend moment detail list is empty')
                    opened_detail = True
                    listitem = detail_items[0]
                    content, photo_num, video_num, post_time = parse_friend_post(listitem)
                    detail_fingerprint = _build_post_fingerprint(
                        content, post_time, photo_num, video_num, current_key
                    )
                    detail_index = recorded_num
                    is_duplicate_detail = detail_fingerprint in seen_post_fingerprints
                    if is_duplicate_detail:
                        log_debug("detail duplicate fingerprint, skip append/save")
                    else:
                        posts.append({'内容': content, '图片数量': photo_num, '视频数量': video_num, '发布时间': post_time})
                        seen_post_fingerprints.add(detail_fingerprint)
                    should_save_detail = True
                    if detail_content_filter is not None:
                        try:
                            should_save_detail = bool(detail_content_filter(content))
                        except Exception:
                            should_save_detail = True
                    if save_detail and should_save_detail and (not is_duplicate_detail):
                        detail_folder = os.path.join(friend_folder, f'{detail_index}')
                        os.makedirs(detail_folder, exist_ok=True)
                        save_media(sns_detail_list, photo_num, detail_folder, content)
                        log_debug(f"detail saved: {detail_folder}")
                    else:
                        log_debug("detail not saved for this item")
                    if not is_duplicate_detail:
                        recorded_num += 1
                    processed_keys.add(current_key)
                    item_failures.pop(current_key, None)
                    unresolved_rounds = 0
                    stagnant_scroll_rounds = 0
                except Exception:
                    unresolved_rounds += 1
                    log_debug(f"process failed key={current_key} unresolved={unresolved_rounds}")
                    fail_count = item_failures.get(current_key, 0) + 1
                    item_failures[current_key] = fail_count
                    if fail_count >= max_failures_per_item:
                        processed_keys.add(current_key)
                        if quick_fingerprint is None:
                            quick_fingerprint = _build_post_fingerprint(
                                quick_content, quick_post_time, quick_photo_num, quick_video_num, current_key
                            )
                        if quick_fingerprint not in seen_post_fingerprints:
                            posts.append({
                                '内容': quick_content,
                                '图片数量': quick_photo_num,
                                '视频数量': quick_video_num,
                                '发布时间': quick_post_time
                            })
                            seen_post_fingerprints.add(quick_fingerprint)
                            recorded_num += 1
                            log_debug("fallback append quick content after repeated detail-open failures")
                        item_failures.pop(current_key, None)
                        unresolved_rounds = 0
                        stagnant_scroll_rounds = 0
                        log_debug(f"mark processed after repeated failures key={current_key} fail_count={fail_count}")
                finally:
                    back_success = False
                    if opened_detail:
                        try:
                            if backbutton.exists(timeout=0.5):
                                backbutton.click_input()
                                time.sleep(0.2)
                                back_success = True
                                log_debug("back button clicked, returned to list")
                            else:
                                log_debug("WARNING: back button not found after opening detail")
                                pyautogui.press('esc')
                                time.sleep(0.2)
                                log_debug("tried ESC key as fallback")
                        except Exception as e:
                            log_debug(f"ERROR returning to list: {e}")
                            try:
                                pyautogui.press('esc')
                                time.sleep(0.2)
                            except Exception:
                                pass
                    else:
                        log_debug("skip back: detail was not opened")
                if unresolved_rounds >= 30:
                    log_debug("exit: unresolved_rounds >= 30")
                    break
                if recorded_num >= number:
                    log_debug("exit: reached target number")
                    break
                continue

            no_pick_rounds += 1
            before_keys = tuple(visible_keys)
            scroll_key = '{PGDN}' if stagnant_scroll_rounds >= 1 else '{DOWN}'
            moments_list.type_keys(scroll_key)
            time.sleep(0.15)
            try:
                after_all_items = [
                    listitem for listitem in moments_list.children(control_type='ListItem')
                    if listitem.class_name() not in not_contents
                ]
            except Exception:
                after_all_items = []
            after_items = [item for item in after_all_items if _is_clickable_in_viewport(item, moments_list)]
            try:
                after_items = sorted(after_items, key=lambda li: li.rectangle().top)
            except Exception:
                pass
            after_keys = tuple(_build_item_key(item) for item in after_items)
            if after_keys == before_keys:
                stagnant_scroll_rounds += 1
                log_debug(f"scroll no change key={scroll_key} stagnant={stagnant_scroll_rounds}")
                if stagnant_scroll_rounds % 10 == 0 and stagnant_scroll_rounds < 80:
                    log_debug(f"stagnant={stagnant_scroll_rounds}, trying viewport refresh")
                    moments_list.type_keys('{PGDN}')
                    time.sleep(0.1)
                    moments_list.type_keys('{PGUP}')
                    time.sleep(0.1)
            else:
                stagnant_scroll_rounds = 0
                unresolved_rounds = 0
                log_debug(f"scroll changed visible window key={scroll_key}")
            if no_pick_rounds >= 120:
                log_debug("exit: no pick progress for 120 rounds")
                break
            if stagnant_scroll_rounds >= 80:
                log_debug("exit: stagnant_scroll_rounds >= 80")
                break
            if recorded_num >= number:
                log_debug("exit: reached target number after scrolling")
                break
    log_debug(f"finished recorded={recorded_num} posts={len(posts)}")
    moments_window.close()
    return posts


def like_posts(recent: Literal['Today', 'Yesterday', 'Week', 'Month'] = 'Today', number: int = None,
               callback: Callable[[str], str] = None, is_maximize: bool = None, close_weixin: bool = None) -> list[dict]:
    '''
    增强版：给朋友圈内最近发布的内容点赞和评论，使用 SNS 偏移量 + 绿色按钮检测。
    '''
    def parse_listitem(listitem: ListItemWrapper):
        video_num = 0
        photo_num = 0
        text = listitem.window_text()
        text = text.strip(' ').replace('\n', '')
        splited_text = text.split(' ')
        possible_timestamps = [text for text in splited_text if sns_timestamp_pattern.match(text)]
        post_time = possible_timestamps[-1]
        if re.search(r'\s包含(\d+)张图片\s', text):
            photo_num = int(re.search(r'\s包含(\d+)张图片\s', text).group(1))
        if re.search(r'\s视频\s', text):
            video_num = 1
        content = re.sub(rf'\s((包含\d+张图片\s|视频\s).*{post_time})', '', text)
        return content, photo_num, video_num, post_time

    def like(content_listitem: ListItemWrapper):
        mouse.move(coords=center_point)
        ellipsis_area = (
            content_listitem.rectangle().right - _SNS_ELLIPSIS_X_OFFSET,
            content_listitem.rectangle().bottom - _SNS_ELLIPSIS_Y_OFFSET
        )
        mouse.click(coords=ellipsis_area)
        if like_button.exists(timeout=0.1):
            like_button.click_input()

    def comment(content_listitem: ListItemWrapper, comment_listitem: ListItemWrapper, content: str):
        mouse.move(coords=center_point)
        ellipsis_area = (
            content_listitem.rectangle().right - _SNS_ELLIPSIS_X_OFFSET,
            content_listitem.rectangle().bottom - _SNS_ELLIPSIS_Y_OFFSET
        )
        mouse.click(coords=ellipsis_area)
        reply = callback(content)
        if comment_button.exists(timeout=0.1) and reply:
            comment_button.click_input()
            pyautogui.hotkey('ctrl', 'a')
            pyautogui.press('backspace')
            SystemSettings.copy_text_to_windowsclipboard(text=reply)
            pyautogui.hotkey('ctrl', 'v')
            if comment_listitem is not None:
                rectangle = comment_listitem.rectangle()
                _click_send_button(
                    rectangle,
                    x_offset=_SNS_SEND_LIST_X_OFFSET,
                    y_offset=_SNS_SEND_LIST_Y_OFFSET
                )
            else:
                print('[debug:comment] comment_listitem missing, skip send (enter disabled)')

    if is_maximize is None:
        is_maximize = GlobalConfig.is_maximize
    if close_weixin is None:
        close_weixin = GlobalConfig.close_weixin

    posts = []
    liked_num = 0
    minutes = {f'{i}分钟前' for i in range(1, 60)}
    hours = {f'{i}小时前' for i in range(1, 24)}
    month_days = {f'{i}天前' for i in range(1, 31)}
    week_days = {f'{i}天前' for i in range(1, 8)}
    week_days.update(minutes)
    week_days.update(hours)
    month_days.update(week_days)
    sns_timestamp_pattern = _regex_patterns.Sns_Timestamp_pattern
    not_contents = ['mmui::TimelineCommentCell', 'mmui::TimelineCell', 'mmui::TimelineAdGridImageCell']
    moments_window = Navigator.open_moments(is_maximize=is_maximize, close_weixin=close_weixin)
    like_button = moments_window.child_window(control_type='Button', title='赞')
    comment_button = moments_window.child_window(control_type='Button', title='评论')
    moments_list = moments_window.child_window(**Lists.MomentsList)
    center_point = (moments_list.rectangle().mid_point().x, moments_list.rectangle().mid_point().y)
    moments_list.type_keys('{HOME}')
    if moments_list.children(control_type='ListItem'):
        while True:
            moments_list.type_keys('{DOWN}', pause=0.1)
            selected = [listitem for listitem in moments_list.children(control_type='ListItem') if listitem.has_keyboard_focus()]
            if selected and selected[0].class_name() not in not_contents:
                content, photo_num, video_num, post_time = parse_listitem(selected[0])
                posts.append({'内容': content, '图片数量': photo_num, '视频数量': video_num, '发布时间': post_time})
                like(selected[0])
                liked_num += 1
                if callback is not None:
                    comment_listitem = Tools.get_next_item(moments_list, selected[0])
                    comment(selected[0], comment_listitem, content)
                if isinstance(number, int) and liked_num >= number:
                    break
                if recent == 'Today' and ('昨天' in post_time or '天前' in post_time):
                    break
                if recent == 'Yesterday' and '天前' in post_time:
                    break
                if recent == 'Week' and post_time not in week_days:
                    break
                if recent == 'Month' and post_time not in month_days:
                    break
    if recent == 'Today':
        posts = [post for post in posts if '天' not in post.get('发布时间')]
    if recent == 'Yesterday':
        posts = [post for post in posts if post.get('发布时间') == '昨天']
    if recent == 'Week':
        posts = [post for post in posts if post.get('发布时间') in week_days]
    if recent == 'Month':
        posts = [post for post in posts if post.get('发布时间') in month_days]
    moments_window.close()
    return posts


def like_friend_posts(friend: str, number: int, callback: Callable[[str], str] = None,
                      is_maximize: bool = None, close_weixin: bool = None) -> list[dict]:
    '''
    增强版：给某个好友朋友圈内发布的内容点赞和评论，使用 SNS 偏移量。
    '''
    def parse_friend_post(listitem: ListItemWrapper):
        video_num = 0
        photo_num = 0
        text = listitem.window_text()
        text = text.replace(friend, '')
        post_time_match = sns_detail_pattern.search(text)
        post_time = post_time_match.group(0) if post_time_match is not None else ''
        if re.search(r'\s包含(\d+)张图片\s', text):
            photo_num = int(re.search(r'\s包含(\d+)张图片\s', text).group(1))
        if post_time and re.search(rf'\s视频\s{re.escape(post_time)}', text):
            video_num = 1
        if post_time:
            content = re.sub(rf'\s((包含\d+张图片\s|视频\s).*{re.escape(post_time)})\s', '', text)
        else:
            content = re.sub(r'\s(包含\d+张图片\s|视频\s?)\s*', ' ', text)
        content = content.strip()
        return content, photo_num, video_num, post_time

    def like(listview: ListViewWrapper, content_listitem: ListItemWrapper):
        center_point = (listview.rectangle().mid_point().x, listview.rectangle().mid_point().y)
        mouse.move(coords=center_point)
        ellipsis_area = (
            content_listitem.rectangle().right - _SNS_ELLIPSIS_X_OFFSET,
            content_listitem.rectangle().bottom - _SNS_ELLIPSIS_Y_OFFSET
        )
        mouse.click(coords=ellipsis_area)
        if like_button.exists(timeout=0.1):
            like_button.click_input()

    def comment(listview: ListViewWrapper, content_listitem: ListItemWrapper, content: str):
        comment_listitem = Tools.get_next_item(listview, content_listitem)
        center_point = (listview.rectangle().mid_point().x, listview.rectangle().mid_point().y)
        mouse.move(coords=center_point)
        ellipsis_area = (
            content_listitem.rectangle().right - _SNS_ELLIPSIS_X_OFFSET,
            content_listitem.rectangle().bottom - _SNS_ELLIPSIS_Y_OFFSET
        )
        mouse.click(coords=ellipsis_area)
        reply = callback(content)
        if comment_button.exists(timeout=0.1) and reply:
            comment_button.click_input()
            pyautogui.hotkey('ctrl', 'a')
            pyautogui.press('backspace')
            SystemSettings.copy_text_to_windowsclipboard(text=reply)
            pyautogui.hotkey('ctrl', 'v')
            if comment_listitem is not None:
                rectangle = comment_listitem.rectangle()
                _click_send_button(
                    rectangle,
                    x_offset=_SNS_SEND_LIST_X_OFFSET,
                    y_offset=_SNS_SEND_LIST_Y_OFFSET
                )
            else:
                print('[debug:comment] comment_listitem missing, skip send (enter disabled)')

    if is_maximize is None:
        is_maximize = GlobalConfig.is_maximize
    if close_weixin is None:
        close_weixin = GlobalConfig.close_weixin
    posts = []
    liked_num = 0
    sns_detail_pattern = _regex_patterns.Snsdetail_Timestamp_pattern
    not_contents = ['mmui::AlbumBaseCell', 'mmui::AlbumTopCell']
    moments_window = Navigator.open_friend_moments(friend=friend, is_maximize=is_maximize, close_weixin=close_weixin)
    backbutton = moments_window.child_window(**Buttons.BackButton)
    win32gui.SendMessage(moments_window.handle, win32con.WM_SYSCOMMAND, win32con.SC_MAXIMIZE, 0)
    moments_list = moments_window.child_window(**Lists.MomentsList)
    sns_detail_list = moments_window.child_window(**Lists.SnsDetailList)
    like_button = moments_window.child_window(control_type='Button', title='赞')
    comment_button = moments_window.child_window(control_type='Button', title='评论')
    moments_list.type_keys('{PGDN}')
    moments_list.type_keys('{PGUP}')
    contents = [listitem for listitem in moments_list.children(control_type='ListItem') if listitem.class_name() not in not_contents]
    if contents:
        while True:
            moments_list.type_keys('{DOWN}')
            selected = [listitem for listitem in moments_list.children(control_type='ListItem') if listitem.has_keyboard_focus()]
            if selected and selected[0].class_name() not in not_contents:
                selected[0].click_input()
                content_listitem = sns_detail_list.children(control_type='ListItem')[0]
                content, photo_num, video_num, post_time = parse_friend_post(content_listitem)
                posts.append({'内容': content, '图片数量': photo_num, '视频数量': video_num, '发布时间': post_time})
                like(sns_detail_list, content_listitem)
                if callback is not None:
                    comment(sns_detail_list, content_listitem, content)
                liked_num += 1
                backbutton.click_input()
                if Tools.is_sns_at_bottom(moments_list, selected[0]):
                    break
            if liked_num >= number:
                break
    moments_window.close()
    return posts


# ---------------------------------------------------------------------------
# 3h. 新功能方法
# ---------------------------------------------------------------------------

def fetch_and_comment_friend_moment(
    friend: str,
    ai_callback,
    target_folder: str = None,
    is_maximize: bool = None,
    close_weixin: bool = None,
    include_keywords: list = None,
    exclude_keywords: list = None,
    last_fingerprint: str = None
) -> dict:
    """Open one friend's moments once, read + infer + comment."""
    def resolve_child_window(moments_window, criteria: dict, error_hint: str, retries: int = 4, wait: float = 0.12):
        last_error = None
        for _ in range(retries):
            try:
                ctrl = moments_window.child_window(**criteria)
                if ctrl.exists(timeout=0.2):
                    return ctrl
            except Exception as e:
                last_error = e
            time.sleep(wait)
        if last_error is not None:
            raise last_error
        raise RuntimeError(error_hint)

    if is_maximize is None:
        is_maximize = GlobalConfig.is_maximize
    if close_weixin is None:
        close_weixin = GlobalConfig.close_weixin
    if target_folder is None:
        target_folder = os.path.join(os.getcwd(), 'rush_moments_cache')
    os.makedirs(target_folder, exist_ok=True)

    result = {
        'success': False,
        'content': '',
        'image_count': 0,
        'publish_time': '',
        'fingerprint': '',
        'ai_answer': None,
        'comment_posted': False,
        'error': None,
        'image_paths': [],
        'screenshot_path': '',
        'detail_folder': ''
    }

    moments_window = None
    try:
        moments_window = Navigator.open_friend_moments(friend=friend, is_maximize=False, close_weixin=False)
        if is_maximize:
            try:
                win32gui.SendMessage(moments_window.handle, win32con.WM_SYSCOMMAND, win32con.SC_MAXIMIZE, 0)
            except Exception:
                pass

        moments_list = resolve_child_window(moments_window, Lists.MomentsList, 'cannot locate moments list')
        moments_list.type_keys('{PGDN}')
        moments_list.type_keys('{PGUP}')
        not_contents = ['mmui::AlbumBaseCell', 'mmui::AlbumTopCell']
        selected_item = None
        for _ in range(6):
            moments_list.type_keys('{DOWN}', pause=0.05)
            selected = [li for li in moments_list.children(control_type='ListItem') if li.has_keyboard_focus()]
            if selected and selected[0].class_name() not in not_contents:
                selected_item = selected[0]
                selected_item.click_input()
                break
        if selected_item is None:
            result['error'] = 'cannot locate first friend moment'
            return result

        sns_detail_list = resolve_child_window(moments_window, Lists.SnsDetailList, 'cannot locate friend moment detail list')
        detail_items = sns_detail_list.children(control_type='ListItem')
        if not detail_items:
            result['error'] = 'cannot read moment detail list'
            return result
        detail_item = detail_items[0]
        content = detail_item.window_text().strip()

        image_count = 0
        publish_time = ''
        m = re.search(r'包含(\d+)张图片', content)
        if m:
            image_count = int(m.group(1))
        for part in content.split():
            if ('分钟' in part) or ('小时' in part) or ('昨天' in part) or (':' in part):
                publish_time = part
                break

        result['content'] = content
        result['image_count'] = image_count
        result['publish_time'] = publish_time

        result['fingerprint'] = _build_post_fingerprint(
            content=content,
            post_time=publish_time,
            photo_num=image_count,
            video_num=0,
            item_key=None,
        )

        if last_fingerprint and result['fingerprint'] == last_fingerprint:
            result['success'] = True
            return result

        if include_keywords and not any(kw in content for kw in include_keywords):
            result['success'] = True
            return result
        if exclude_keywords and any(kw in content for kw in exclude_keywords):
            result['success'] = True
            return result

        run_folder = os.path.join(target_folder, f'{friend}_{int(time.time() * 1000)}')
        os.makedirs(run_folder, exist_ok=True)
        result['detail_folder'] = run_folder

        if image_count > 0:
            try:
                sns_detail_list_rect = sns_detail_list.rectangle()
                comment_items = sns_detail_list.children(control_type='ListItem')
                if len(comment_items) > 1:
                    ci_rect = comment_items[1].rectangle()
                    mouse.click(coords=(ci_rect.left + 120, ci_rect.top - 80))
                else:
                    mouse.click(coords=(sns_detail_list_rect.mid_point().x, sns_detail_list_rect.mid_point().y))
                time.sleep(0.3)
                pyautogui.press('left', presses=image_count, interval=0.15)
                time.sleep(0.1)
                right_click_pos = (sns_detail_list_rect.mid_point().x + 20, sns_detail_list_rect.mid_point().y + 25)
                for i in range(image_count):
                    try:
                        sns_detail_list.right_click_input(coords=right_click_pos)
                        copy_menu = moments_window.child_window(**MenuItems.CopyMenuItem)
                        if copy_menu.exists(timeout=0.3):
                            copy_menu.click_input()
                            time.sleep(0.5)
                            img_path = os.path.join(run_folder, f'{i}.png')
                            SystemSettings.save_pasted_image(img_path)
                            if os.path.isfile(img_path):
                                result['image_paths'].append(img_path)
                    finally:
                        pyautogui.press('right', interval=0.05)
                pyautogui.press('esc')
                time.sleep(0.1)
            except Exception:
                try:
                    pyautogui.press('esc')
                except Exception:
                    pass

        if not result['image_paths']:
            try:
                screenshot_path = os.path.join(run_folder, 'content_screenshot.png')
                detail_item.capture_as_image().save(screenshot_path)
                result['screenshot_path'] = screenshot_path
                result['image_paths'] = [screenshot_path]
            except Exception:
                pass

        result['success'] = True
        ai_answer = ai_callback(content, result['image_paths'])
        result['ai_answer'] = ai_answer
        if isinstance(ai_answer, list):
            answer_list = [a.strip() for a in ai_answer if isinstance(a, str) and a.strip()]
        elif isinstance(ai_answer, str) and ai_answer.strip():
            answer_list = [ai_answer.strip()]
        else:
            answer_list = []
        if not answer_list:
            return result

        comment_cell = None
        for _item in sns_detail_list.children(control_type='ListItem'):
            if 'Comment' in _item.class_name():
                comment_cell = _item
                break
        if comment_cell is None and len(detail_items) > 1:
            comment_cell = detail_items[-1]

        posted = comment_flow(
            moments_window, detail_item, answer_list,
            anchor_mode='detail', anchor_source=comment_cell,
            use_offset_fix=True, clear_first=False
        )
        result['comment_posted'] = posted
        if not posted and not result.get('error'):
            result['error'] = 'comment flow finished but send was not verified'
        return result

    except Exception as e:
        result['error'] = str(e)
        import traceback
        traceback.print_exc()
        return result
    finally:
        if moments_window is not None and close_weixin:
            try:
                moments_window.close()
            except Exception:
                pass


def fetch_and_comment_from_moments_feed(
    target_author: str,
    ai_callback,
    target_folder: str = None,
    is_maximize: bool = None,
    close_weixin: bool = None,
    include_keywords: list = None,
    exclude_keywords: list = None,
    last_fingerprint: str = None,
    refresh_first: bool = True,
    moments_window: WindowSpecification = None,
    expected_publish_dt: datetime = None,
    publish_time_tolerance_minutes: int = 2,
    override_answer=None,
) -> dict:
    """Read first valid post in global feed, infer and comment in list mode."""
    def refresh_moments_window(current_window, retries: int = 4, wait: float = 0.12):
        last_error = None
        for _ in range(retries):
            try:
                if current_window is not None and current_window.exists(timeout=0.1):
                    return current_window
            except Exception as exc:
                last_error = exc
            try:
                fresh_window = desktop.window(**Windows.MomentsWindow)
                if fresh_window.exists(timeout=0.2):
                    return fresh_window
            except Exception as exc:
                last_error = exc
            time.sleep(wait)
        if last_error is not None:
            raise last_error
        raise RuntimeError('cannot locate moments window')

    def resolve_child_window(mw, criteria: dict, error_hint: str, retries: int = 4, wait: float = 0.12):
        last_error = None
        for _ in range(retries):
            try:
                ctrl = mw.child_window(**criteria)
                if ctrl.exists(timeout=0.2):
                    return ctrl
            except Exception as e:
                last_error = e
            time.sleep(wait)
        if last_error is not None:
            raise last_error
        raise RuntimeError(error_hint)

    def resolve_feed_comment_anchor(moments_list, selected_item):
        try:
            items = moments_list.children(control_type='ListItem')
        except Exception:
            return None
        selected_idx = -1
        for idx, item in enumerate(items):
            if item == selected_item:
                selected_idx = idx
                break
        if selected_idx >= 0:
            for offset in range(1, 5):
                idx = selected_idx + offset
                if idx >= len(items):
                    break
                candidate = items[idx]
                try:
                    cls_name = candidate.class_name()
                except Exception:
                    cls_name = ""
                if "TimelineCommentCell" in cls_name:
                    return candidate
        return Tools.get_next_item(moments_list, selected_item)

    def reacquire_feed_list(retries: int = 6, wait: float = 0.12):
        nonlocal moments_window
        last_error = None
        for _ in range(retries):
            try:
                moments_window = refresh_moments_window(moments_window, retries=2, wait=0.06)
                feed_list = resolve_child_window(
                    moments_window, Lists.MomentsList, 'cannot locate moments feed list'
                )
                try:
                    feed_list.set_focus()
                except Exception:
                    try:
                        lr = feed_list.rectangle()
                        x = max(lr.left + 20, min(lr.right - 20, lr.mid_point().x))
                        y = max(lr.top + 20, min(lr.bottom - 20, lr.mid_point().y))
                        mouse.click(coords=(x, y))
                        time.sleep(0.05)
                    except Exception:
                        pass
                return feed_list
            except Exception as exc:
                last_error = exc
                try:
                    pyautogui.press('esc')
                except Exception:
                    pass
                time.sleep(wait)
        if last_error is not None:
            raise last_error
        raise RuntimeError('cannot locate moments feed list')

    def _extract_images_via_copy_menu(
        *,
        run_folder: str,
        image_count: int,
        open_candidates: list[tuple[int, int]],
        right_click_pos: tuple[int, int],
    ) -> tuple[list[str], bool]:
        """Extract viewer images by copy menu + clipboard save.

        Returns:
            (paths, opened)
            - paths: extracted image paths
            - opened: whether any candidate entered viewer/copy-menu flow
        """
        extracted_paths: list[str] = []
        opened = False
        for open_pos in open_candidates:
            try:
                mouse.click(coords=open_pos)
                time.sleep(0.08)
                current_paths: list[str] = []
                copy_seen = False
                for i in range(image_count):
                    img_path = os.path.join(run_folder, f'{i}.png')
                    try:
                        if os.path.isfile(img_path):
                            os.remove(img_path)
                    except Exception:
                        pass

                    try:
                        mouse.right_click(coords=right_click_pos)
                    except Exception:
                        pass

                    copy_menu = moments_window.child_window(**MenuItems.CopyMenuItem)
                    if not copy_menu.exists(timeout=0.2):
                        current_paths = []
                        break
                    copy_seen = True
                    opened = True

                    try:
                        copy_menu.click_input()
                    except Exception:
                        try:
                            mouse.click(coords=right_click_pos)
                        except Exception:
                            pass

                    # Give clipboard a short settle time.
                    time.sleep(0.10)
                    try:
                        SystemSettings.save_pasted_image(img_path)
                    except Exception:
                        pass

                    if not os.path.isfile(img_path):
                        current_paths = []
                        break
                    try:
                        if os.path.getsize(img_path) <= 0:
                            current_paths = []
                            break
                    except Exception:
                        current_paths = []
                        break

                    current_paths.append(img_path)
                    if i < image_count - 1:
                        pyautogui.press('right', interval=0.08)
                        time.sleep(0.08)

                if current_paths:
                    extracted_paths = current_paths
                    break
                if copy_seen:
                    # Copy menu was visible but extraction failed; try next open candidate.
                    continue
            finally:
                try:
                    pyautogui.press('esc')
                    time.sleep(0.05)
                except Exception:
                    pass
        return extracted_paths, opened

    if is_maximize is None:
        is_maximize = GlobalConfig.is_maximize
    if close_weixin is None:
        close_weixin = GlobalConfig.close_weixin
    if target_folder is None:
        target_folder = os.path.join(os.getcwd(), 'rush_moments_cache_feed')
    os.makedirs(target_folder, exist_ok=True)

    result = {
        'success': False,
        'author': '',
        'content': '',
        'image_count': 0,
        'publish_time': '',
        'fingerprint': '',
        'ai_answer': None,
        'comment_attempted': False,
        'comment_posted': False,
        'error': None,
        'image_paths': [],
        'screenshot_path': '',
        'detail_folder': ''
    }

    created_window = False
    now_for_publish_eval = datetime.now()
    try:
        publish_time_tolerance_minutes = int(publish_time_tolerance_minutes)
    except Exception:
        publish_time_tolerance_minutes = 2
    if publish_time_tolerance_minutes < 1:
        publish_time_tolerance_minutes = 1
    skip_stale_posts = os.getenv("PYWEIXIN_SKIP_STALE_POSTS", "1").strip().lower() in {
        "1", "true", "yes", "on"
    }
    try:
        max_post_age_minutes = int(os.getenv("PYWEIXIN_MAX_POST_AGE_MINUTES", "30"))
    except Exception:
        max_post_age_minutes = 30
    if max_post_age_minutes < 1:
        max_post_age_minutes = 1

    def parse_feed_listitem(listitem: ListItemWrapper):
        sns_timestamp_pattern = _regex_patterns.Sns_Timestamp_pattern
        text = listitem.window_text().strip().replace('\n', ' ')
        text = re.sub(r'\s+', ' ', text)
        post_time = ''
        image_count = 0
        possible_timestamps = [part for part in text.split(' ') if sns_timestamp_pattern.match(part)]
        if possible_timestamps:
            post_time = possible_timestamps[-1]
            match = re.search(rf'\s包含(\d+)张图片\s{post_time}', text)
            if match:
                image_count = int(match.group(1))
            content = re.sub(rf'\s(包含\d+张图片\s{post_time}|视频\s{post_time}|{post_time})', '', text).strip()
        else:
            if '刚刚' in text:
                post_time = '刚刚'
                content = re.sub(r'\s刚刚', '', text).strip()
            else:
                content = text
        author = ''
        body = content
        if content:
            parts = content.split(' ', 1)
            author = parts[0].strip()
            body = parts[1].strip() if len(parts) > 1 else ''
        return author, body, content, image_count, post_time

    try:
        if moments_window is None:
            moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
            created_window = True
        moments_window = refresh_moments_window(moments_window, retries=8, wait=0.08)

        if is_maximize:
            try:
                win32gui.SendMessage(moments_window.handle, win32con.WM_SYSCOMMAND, win32con.SC_MAXIMIZE, 0)
            except Exception:
                pass

        try:
            back_button = moments_window.child_window(**Buttons.BackButton)
            if back_button.exists(timeout=0.1):
                back_button.click_input()
                time.sleep(0.1)
        except Exception:
            pass

        if refresh_first:
            refresh_button = moments_window.child_window(**Buttons.RefreshButton)
            if refresh_button.exists(timeout=0.2):
                refresh_button.click_input()
                time.sleep(0.15)

        moments_list = reacquire_feed_list(retries=8, wait=0.12)
        try:
            moments_list.type_keys('{HOME}')
        except Exception:
            pyautogui.press('home')
        not_contents = ['mmui::TimelineCommentCell', 'mmui::TimelineCell', 'mmui::TimelineAdGridImageCell']
        selected_item = None
        selected_parsed = None
        fallback_parsed = None
        fallback_fingerprint = ''
        for _ in range(15):
            try:
                moments_list.type_keys('{DOWN}', pause=0.05)
            except Exception:
                pyautogui.press('down')
            try:
                selected = [li for li in moments_list.children(control_type='ListItem') if li.has_keyboard_focus()]
            except Exception:
                moments_list = reacquire_feed_list(retries=4, wait=0.1)
                selected = [li for li in moments_list.children(control_type='ListItem') if li.has_keyboard_focus()]
            if selected and selected[0].class_name() not in not_contents:
                candidate = selected[0]
                c_author, c_body, c_content, c_image_count, c_publish_time = parse_feed_listitem(candidate)
                c_item_key = _build_item_key(candidate)
                c_fingerprint = _build_post_fingerprint(
                    content=c_content,
                    post_time=c_publish_time,
                    photo_num=c_image_count,
                    video_num=0,
                    item_key=c_item_key,
                )
                if fallback_parsed is None:
                    fallback_parsed = (
                        c_author, c_body, c_content, c_image_count, c_publish_time
                    )
                    fallback_fingerprint = c_fingerprint

                _preview = (c_content[:60] + '..') if len(c_content) > 60 else c_content
                print(f'[debug:select] candidate author={c_author!r} time={c_publish_time!r} img={c_image_count} fp={c_fingerprint[:8]} content={_preview!r}')

                if target_author:
                    author_hit = (c_author == target_author) or (target_author in c_author)
                    if not author_hit:
                        print(f'[debug:select]   SKIP: author mismatch (want {target_author!r})')
                        continue
                if expected_publish_dt is None and last_fingerprint and c_fingerprint == last_fingerprint:
                    print(f'[debug:select]   SKIP: same fingerprint as last')
                    continue
                age_minutes = _parse_relative_post_age_minutes(c_publish_time)
                if expected_publish_dt is not None:
                    if age_minutes is None:
                        print(f'[debug:select]   SKIP: cannot parse age from {c_publish_time!r}')
                        continue
                    inferred_publish_dt = now_for_publish_eval - timedelta(minutes=age_minutes)
                    delta_minutes = abs(
                        (inferred_publish_dt - expected_publish_dt).total_seconds()
                    ) / 60.0
                    print(f'[debug:select]   age={age_minutes}min, inferred={inferred_publish_dt.strftime("%H:%M")}, expected={expected_publish_dt.strftime("%H:%M")}, delta={delta_minutes:.1f}min, tol={publish_time_tolerance_minutes}min')
                    if delta_minutes > publish_time_tolerance_minutes:
                        print(f'[debug:select]   SKIP: delta {delta_minutes:.1f} > tolerance {publish_time_tolerance_minutes}')
                        continue
                elif skip_stale_posts:
                    if age_minutes is not None and age_minutes > max_post_age_minutes:
                        print(f'[debug:select]   SKIP: stale post ({age_minutes}min > {max_post_age_minutes}min)')
                        continue

                c_text_for_filter = c_body if c_body else c_content
                if include_keywords and not any(kw in c_text_for_filter for kw in include_keywords):
                    print(f'[debug:select]   SKIP: no include keyword match')
                    continue
                if exclude_keywords and any(kw in c_text_for_filter for kw in exclude_keywords):
                    print(f'[debug:select]   SKIP: exclude keyword matched')
                    continue

                print(f'[debug:select]   ACCEPTED')
                selected_item = candidate
                selected_parsed = (
                    c_author, c_body, c_content, c_image_count, c_publish_time, c_fingerprint
                )
                break
        if selected_item is None:
            if fallback_parsed is not None:
                author, body, content, image_count, publish_time = fallback_parsed
                result['author'] = author
                result['content'] = content
                result['image_count'] = image_count
                result['publish_time'] = publish_time
                result['fingerprint'] = fallback_fingerprint
                result['success'] = True
                return result
            result['error'] = 'cannot locate first valid feed item'
            return result

        if selected_parsed is None:
            author, body, content, image_count, publish_time = parse_feed_listitem(selected_item)
            item_key = _build_item_key(selected_item)
            fingerprint = _build_post_fingerprint(
                content=content,
                post_time=publish_time,
                photo_num=image_count,
                video_num=0,
                item_key=item_key,
            )
        else:
            author, body, content, image_count, publish_time, fingerprint = selected_parsed

        result['author'] = author
        result['content'] = content
        result['image_count'] = image_count
        result['publish_time'] = publish_time
        result['fingerprint'] = fingerprint
        text_for_filter = body if body else content

        prefix = target_author.strip() if target_author else 'feed'
        run_folder = os.path.join(target_folder, f'{prefix}_{int(time.time() * 1000)}')
        os.makedirs(run_folder, exist_ok=True)
        result['detail_folder'] = run_folder

        result['success'] = True

        # override_answer 短路：跳过图片提取和 AI，直接定位帖子发评论
        if override_answer is not None:
            print(f'[debug:override] skipping image/AI, posting cached answer directly')
            answer_list = []
            if isinstance(override_answer, list):
                answer_list = [str(a).strip() for a in override_answer if a and str(a).strip()]
            elif isinstance(override_answer, str) and override_answer.strip():
                answer_list = [override_answer.strip()]
            if not answer_list:
                result['ai_answer'] = override_answer
                return result
            result['ai_answer'] = override_answer

            moments_list = reacquire_feed_list(retries=10, wait=0.15)
            try:
                moments_list.type_keys('{HOME}')
            except Exception:
                pyautogui.press('home')
            time.sleep(0.1)

            _selected_item = None
            for nav_i in range(15):
                try:
                    moments_list.type_keys('{DOWN}', pause=0.05)
                except Exception:
                    pyautogui.press('down')
                try:
                    candidates = [li for li in moments_list.children(control_type='ListItem') if li.has_keyboard_focus()]
                except Exception:
                    moments_list = reacquire_feed_list(retries=4, wait=0.1)
                    continue
                if not candidates or candidates[0].class_name() in ('TimelineCommentCell', 'TimelineSnsAdCell'):
                    continue
                _cand = candidates[0]
                _c_author, _c_body, _c_content, _c_img, _c_time = parse_feed_listitem(_cand)
                _c_fp = _build_post_fingerprint(
                    content=_c_content, post_time=_c_time,
                    photo_num=_c_img, video_num=0,
                    item_key=_build_item_key(_cand),
                )
                if _c_fp == fingerprint:
                    _selected_item = _cand
                    print(f'[debug:override] matched target post by fingerprint at nav #{nav_i + 1}')
                    break
                else:
                    print(f'[debug:override] nav #{nav_i + 1} fingerprint mismatch, skip')

            if _selected_item is None:
                result['error'] = 'cannot re-acquire target post for override comment (fingerprint mismatch)'
                return result

            _comment_listitem = resolve_feed_comment_anchor(moments_list, _selected_item)
            _win_rect = moments_window.rectangle()
            _center_point = (_win_rect.mid_point().x, _win_rect.mid_point().y)

            result['comment_attempted'] = True
            print(f'[debug:override] calling comment_flow with answers={answer_list}')
            posted = comment_flow(
                moments_window, _selected_item, answer_list,
                anchor_mode='list', anchor_source=_comment_listitem,
                use_offset_fix=False, clear_first=False,
                pre_move_coords=_center_point
            )
            result['comment_posted'] = posted
            if not posted and not result.get('error'):
                result['error'] = 'override comment flow finished but send was not verified'
            return result
        # Force enable Hook if not explicitly disabled.
        if os.environ.get('PYWEIXIN_HOOK_ENABLED') is None:
            os.environ['PYWEIXIN_HOOK_ENABLED'] = '1'

        _hook_dispatcher = None
        _use_hook = False
        requested_hook_batch_mode_early = os.environ.get(
            "PYWEIXIN_HOOK_BATCH_MODE", "piggyback"
        ).strip().lower()
        if requested_hook_batch_mode_early not in {
            "piggyback", "parallel", "serial", "fast_first_batch"
        }:
            requested_hook_batch_mode_early = "piggyback"
        fast_first_pre_hook_enabled = os.environ.get(
            "PYWEIXIN_FAST_FIRST_PRE_HOOK", "0"
        ).strip().lower() in {"1", "true", "yes", "on"}
        first_answer_mode_early = os.environ.get(
            "PYWEIXIN_FIRST_ANSWER_MODE", "auto"
        ).strip().lower()
        if os.environ.get('PYWEIXIN_HOOK_ENABLED', '0') == '1':
            try:
                from .comment_dispatcher import CommentDispatcher
                # 注意：此时还没有 comment_listitem (是在 reacquire 后才有的)，
                # 但 Hook 发送并不依赖 anchor_source (除非 UI fallback)。
                # 这里主要为了拿 _hook_sender。如果 fall back UI，需要后续 re-init 或传入。
                # 暂时先用 None 初始化 UI sender 相关的部分，仅用于 Hook。
                _hook_dispatcher = CommentDispatcher.from_env(
                    moments_window=moments_window, 
                    content_item=None, # 暂时拿不到
                    anchor_mode='list', 
                    anchor_source=None, 
                )
                _use_hook = _hook_dispatcher._hook_sender is not None
                if _use_hook:
                    print('[debug:stream] hook dispatcher active (pre-init)')
            except Exception as e:
                print(f'[debug:stream] hook dispatcher init error: {e}')

        first_comment_done = False
        instant_first_answer = None  # if we manage to post an instant answer pre-image, store it for dedup/reporting
        
        # [Optimization] Instant Text-Match Comment (Zero Latency)
        # Check if the text content matches any known answer or simple math BEFORE starting AI.
        if _use_hook and _hook_dispatcher and (
            requested_hook_batch_mode_early != "fast_first_batch" or fast_first_pre_hook_enabled
        ):
            try:
                from pyweixin.rush_callback_multi import TemplateMatchCommentSource
                from pyweixin.rush_types import QuestionTemplate
                import json
                
                # Load configs manually
                config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
                known_answers_path = os.path.join(config_dir, "known_answers.json")
                rush_event_path = os.path.join(config_dir, "rush_event.json")
                
                # Load known answers
                known_answers = {}
                if os.path.isfile(known_answers_path):
                    try:
                        with open(known_answers_path, 'r', encoding='utf-8-sig') as f:
                            known_answers = json.load(f)
                    except Exception as e:
                        print(f"[debug:stream] failed to load known_answers: {e}")

                # Load templates
                templates = []
                if os.path.isfile(rush_event_path):
                    try:
                        with open(rush_event_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            # rush_event.json structure might be list or dict with "templates"
                            # rush_config usually has "templates": [...]
                            # If it's a list directly:
                            raw_list = []
                            if isinstance(data, list):
                                raw_list = data
                            elif isinstance(data, dict):
                                raw_list = data.get("templates", [])
                            
                            for item in raw_list:
                                templates.append(QuestionTemplate.from_mapping(item))
                    except Exception as e:
                        print(f"[debug:stream] failed to load templates: {e}")

                tm_source = TemplateMatchCommentSource(
                    known_answers=known_answers,
                    templates=templates,
                    enable_math=True
                )
                
                instant_answer = tm_source.generate(text_for_filter, [])
                if instant_answer:
                    instant_answer = str(instant_answer).strip()
                    print(f"[debug:stream] Instant Text-Match found: {instant_answer}")
                    hr = _hook_dispatcher.post_comment(
                        instant_answer,
                        author=target_author if target_author else "",
                        content_hash=result.get("fingerprint", "")[:16],
                    )
                    if hr.success:
                         print(f"[debug:stream] Instant Hook success: {instant_answer}")
                         first_comment_done = True
                         instant_first_answer = instant_answer
                    else:
                         print(f"[debug:stream] Instant Hook failed: {hr.error_message}")
                         # 答案不丢弃，后续会由 callback 重新产出进入队列
                         _use_hook = False  # Hook 不可用，后续走 UI
            except Exception as e:
                print(f"[debug:stream] Instant Text-Match check failed: {e}")

        import queue as _queue_mod
        print('[debug:main] starting ai_callback with deferred images')
        parallel_start = time.time()

        # --- 延迟图片传递：先启动 callback（散弹/模板立即执行），图片后续传入 ---
        from pyweixin.rush_callback_multi import DeferredImagePaths
        _deferred_images = DeferredImagePaths()
        cb_result = ai_callback(content, _deferred_images)
        is_streaming = hasattr(cb_result, 'get')  # queue.Queue or PriorityAnswerQueue

        # --- 图片提取（在 callback 启动之后） ---
        
        # [Optimization] Pre-Image Hook Attempt (Secondary check if Instant failed/missed)
        # Try to catch instant answers (e.g. OCR templates) and fire Hook comment
        if (
            not first_comment_done
            and is_streaming
            and _hook_dispatcher is not None
            and _use_hook
            and (requested_hook_batch_mode_early != "fast_first_batch" or fast_first_pre_hook_enabled)
        ):
            try:
                # Peek for answer with tiny timeout (50ms)
                pre_answer = cb_result.get(timeout=0.05)
                pre_answer_str = str(pre_answer).strip()
                if pre_answer_str:
                    print(f"[debug:stream] pre-image answer ready: {pre_answer_str}")
                    # Try Hook immediately
                    hr = _hook_dispatcher.post_comment(
                        pre_answer_str,
                        author=result.get("author", ""),
                        content_hash=result.get("fingerprint", "")[:16],
                    )
                    if hr.success:
                        print(f"[debug:stream] pre-image hook success: {pre_answer_str}")
                        first_comment_done = True
                    else:
                        print(f"[debug:stream] pre-image hook failed: {hr.error_message}")
                        cb_result.put(pre_answer)
                        # Hook 不可用且已有答案 → 跳过图片提取，直接走 UI 评论
                        _use_hook = False
                        first_comment_done = False
                        print("[debug:stream] has answer + no hook → skip image extraction, go UI")
            except _queue_mod.Empty:
                pass  # No instant answer, proceed to image extraction

        # 如果已有答案且 Hook 不可用，跳过图片提取直接 reacquire
        _skip_image = (not _use_hook) and is_streaming and (not first_comment_done)
        if _skip_image:
            try:
                _peek = cb_result.get(timeout=0.01)
                cb_result.put(_peek)
                _skip_image = True
                print("[debug:img] skipping image extraction (answer already in queue)")
            except _queue_mod.Empty:
                _skip_image = False  # 没答案，还是要提取图片给 OCR/AI

        _defer_image_extraction = False
        force_defer_fast_first = (
            requested_hook_batch_mode_early == "fast_first_batch"
            and is_streaming
            and image_count > 0
            and (not first_comment_done)
            and first_answer_mode_early != "ai_ocr_only"
            and _use_hook
            and _hook_dispatcher is not None
            and getattr(_hook_dispatcher, "_hook_sender", None) is not None
            and os.environ.get("PYWEIXIN_FAST_FIRST_DEFER_IMAGES", "1").strip().lower()
            in {"1", "true", "yes", "on"}
        )
        if force_defer_fast_first:
            _defer_image_extraction = True
            print("[debug:img] fast_first mode: force defer image extraction until after first comment")
        elif _skip_image:
            _defer_image_extraction = True  # 延迟到第一条评论之后再提取图片
            print("[debug:img] deferring image extraction until after first comment")

        elif image_count > 0:
            try:
                rect = selected_item.rectangle()
                win_rect = moments_window.rectangle()
                viewer_right_click_pos = (win_rect.mid_point().x, win_rect.mid_point().y)
                open_candidates = [
                    (rect.left + 120, rect.bottom - 90),
                    (rect.left + 220, rect.bottom - 120),
                    (rect.mid_point().x, rect.bottom - 100),
                ]
                img_start = time.time()
                _extracted_paths, opened = _extract_images_via_copy_menu(
                    run_folder=run_folder,
                    image_count=image_count,
                    open_candidates=open_candidates,
                    right_click_pos=viewer_right_click_pos,
                )
                img_elapsed = int((time.time() - img_start) * 1000)
                result['image_paths'] = _extracted_paths
                print(f'[debug:img] extracted {len(_extracted_paths)}/{image_count} images ({img_elapsed}ms)')
                if (not opened) and image_count > 0:
                    result['error'] = 'list mode cannot extract images, skipped'
                # 通知 OCR/AI：图片就绪
                _deferred_images.set(_extracted_paths)
            except Exception as e:
                result['error'] = f'list image extraction failed: {e}'
                _deferred_images.set([])  # 通知 OCR/AI：无图片
        else:
            _deferred_images.set([])  # 无图片

        if is_streaming:
            answer_queue = cb_result
            print('[debug:main] streaming mode: answers will arrive via queue')
        else:
            answer_queue = None

        time.sleep(0.15)
        print('[debug:reacquire] re-acquiring feed list')
        moments_list = reacquire_feed_list(retries=10, wait=0.15)
        print(f'[debug:reacquire] feed list acquired')
        try:
            moments_list.type_keys('{HOME}')
        except Exception:
            pyautogui.press('home')
        time.sleep(0.1)

        print('[debug:reacquire] searching for valid content item')
        selected_item = None
        for nav_i in range(15):
            try:
                moments_list.type_keys('{DOWN}', pause=0.05)
            except Exception:
                pyautogui.press('down')
            try:
                candidates = [li for li in moments_list.children(control_type='ListItem') if li.has_keyboard_focus()]
            except Exception:
                moments_list = reacquire_feed_list(retries=4, wait=0.1)
                candidates = [li for li in moments_list.children(control_type='ListItem') if li.has_keyboard_focus()]
            if candidates:
                cls = candidates[0].class_name()
                print(f'[debug:reacquire] nav #{nav_i + 1} focused class={cls}')
                if 'TimelineCommentCell' not in cls and 'TimelineCell' not in cls and 'AdGridImage' not in cls:
                    try:
                        item_text = candidates[0].window_text()[:80]
                    except Exception:
                        item_text = '(cannot read)'
                    # 验证作者匹配，防止评论到错误的帖子
                    if target_author and not item_text.startswith(target_author):
                        print(f'[debug:reacquire] skipped (author mismatch): {item_text}')
                        continue
                    # 验证内容关键字，防止评论到非问题帖子
                    if include_keywords and not any(kw in item_text for kw in include_keywords):
                        print(f'[debug:reacquire] skipped (no keyword match): {item_text}')
                        continue
                    selected_item = candidates[0]
                    print(f'[debug:reacquire] found valid item: {item_text}')
                    break
            else:
                print(f'[debug:reacquire] nav #{nav_i + 1} no focused candidate')

        if selected_item is None:
            print('[debug:reacquire] FAILED - no valid item found after 15 attempts')
            result['error'] = 'cannot re-acquire post for commenting'
            return result

        comment_listitem = resolve_feed_comment_anchor(moments_list, selected_item)
        win_rect = moments_window.rectangle()
        center_point = (win_rect.mid_point().x, win_rect.mid_point().y)
        reacquire_ms = int((time.time() - parallel_start) * 1000)
        print(f'[debug:reacquire] ready to comment ({reacquire_ms}ms since parallel start)')

        if is_streaming:
            result['comment_attempted'] = True
            posted_any = False
            all_answers = []
            comment_count = 0

            requested_hook_batch_mode = os.environ.get(
                "PYWEIXIN_HOOK_BATCH_MODE", "piggyback"
            ).strip().lower()
            if requested_hook_batch_mode not in {
                "piggyback", "parallel", "serial", "fast_first_batch"
            }:
                requested_hook_batch_mode = "piggyback"

            # Hook 路径（通过 PYWEIXIN_HOOK_ENABLED=1 启用）
            # 复用 pre-image 阶段的 _hook_dispatcher（pipe 是单连接的，不能重建）
            _use_hook = False
            if _hook_dispatcher is not None and _hook_dispatcher._hook_sender is not None:
                # Rebind UI sender with the reacquired anchor so Hook failure can
                # gracefully fallback to UI in fast_first_batch path.
                try:
                    from .comment_dispatcher import UICommentSender
                    _ui_anchor = comment_listitem
                    try:
                        _ui_rect = _ui_anchor.rectangle() if _ui_anchor is not None else None
                        if _ui_rect is None or (not _is_valid_anchor_rect(_ui_rect)):
                            _ui_anchor = None
                    except Exception:
                        _ui_anchor = None
                    _hook_dispatcher._ui_sender = UICommentSender(
                        moments_window,
                        selected_item,
                        anchor_mode="list",
                        anchor_source=_ui_anchor,
                        pre_move_coords=center_point,
                    )
                except Exception:
                    pass
                # 检查 capture 是否 fresh，stale 时不走 Hook（避免进 fast_first_batch 后无 UI fallback）
                try:
                    _st = _hook_dispatcher._hook_sender._bridge.status()
                    _age = _st.data.get("capture_age_ms", 99999) if _st.ok else 99999
                    _captured = bool(_st.data.get("state_captured", False)) if _st.ok else False
                    try:
                        _capture_tid = int(_st.data.get("capture_thread_id", 0)) if _st.ok else 0
                    except Exception:
                        _capture_tid = 0
                    _hook_ready = (_age < 10_000) and _captured and (_capture_tid > 0)

                    if _hook_ready:
                        _use_hook = True
                        print(
                            f"[debug:stream] hook dispatcher reused, "
                            f"capture fresh ({_age}ms, tid={_capture_tid})"
                        )
                    else:
                        if requested_hook_batch_mode == "fast_first_batch":
                            _use_hook = True
                            print(
                                f"[debug:stream] hook dispatcher reused but not fully ready "
                                f"(age={_age}ms, captured={_captured}, tid={_capture_tid}), "
                                "keep hook for fast_first_batch probing (UI fallback + piggyback)"
                            )
                        else:
                            print(
                                f"[debug:stream] hook dispatcher reused but hook not ready "
                                f"(age={_age}ms, captured={_captured}, tid={_capture_tid}), using UI"
                            )
                except Exception:
                    print('[debug:stream] hook dispatcher reused but status check failed, using UI')
            elif os.environ.get('PYWEIXIN_HOOK_ENABLED', '0') == '1':
                # pre-image 没建过 dispatcher，尝试新建
                try:
                    from .comment_dispatcher import CommentDispatcher
                    _hook_dispatcher = CommentDispatcher.from_env(
                        moments_window=moments_window, content_item=selected_item,
                        anchor_mode='list', anchor_source=comment_listitem,
                        pre_move_coords=center_point,
                    )
                    _use_hook = _hook_dispatcher._hook_sender is not None
                    if _use_hook:
                        print('[debug:stream] hook dispatcher active')
                    else:
                        print('[debug:stream] hook enabled but DLL not connected, using UI')
                except Exception as e:
                    print(f'[debug:stream] hook dispatcher init error: {e}')
            else:
                print('[debug:stream] hook not enabled')

            # 预开编辑器：在等待 AI/OCR 答案期间先点开评论输入框
            hook_batch_mode = requested_hook_batch_mode
            use_hook_batch = _use_hook and hook_batch_mode in {
                "piggyback", "parallel", "serial", "fast_first_batch"
            }

            def _extract_deferred_images_after_first_comment() -> None:
                nonlocal _defer_image_extraction, comment_listitem
                if not _defer_image_extraction:
                    return
                _defer_image_extraction = False

                if image_count > 0:
                    try:
                        print("[debug:img:deferred] extracting images after first comment")
                        _quick_capture = os.environ.get(
                            "PYWEIXIN_FAST_FIRST_QUICK_CAPTURE", "0"
                        ).strip().lower() in {"1", "true", "yes", "on"}
                        if _quick_capture:
                            _quick_start = time.time()
                            _quick_path = os.path.join(run_folder, "0_quick.png")
                            try:
                                selected_item.capture_as_image().save(_quick_path)
                            except Exception:
                                moments_window.capture_as_image().save(_quick_path)
                            if os.path.isfile(_quick_path):
                                _quick_paths = [_quick_path]
                                _quick_ms = int((time.time() - _quick_start) * 1000)
                                result['image_paths'] = _quick_paths
                                print(
                                    f"[debug:img:deferred] quick captured 1 image "
                                    f"({_quick_ms}ms)"
                                )
                                _deferred_images.set(_quick_paths)
                                try:
                                    comment_listitem = resolve_feed_comment_anchor(moments_list, selected_item)
                                except Exception:
                                    pass
                                return
                        _d_rect = selected_item.rectangle()
                        _d_win_rect = moments_window.rectangle()
                        _d_rclick = (_d_win_rect.mid_point().x, _d_win_rect.mid_point().y)
                        _d_candidates = [
                            (_d_rect.left + 120, _d_rect.bottom - 90),
                            (_d_rect.left + 220, _d_rect.bottom - 120),
                            (_d_rect.mid_point().x, _d_rect.bottom - 100),
                        ]
                        img_start = time.time()
                        _d_paths, _ = _extract_images_via_copy_menu(
                            run_folder=run_folder,
                            image_count=image_count,
                            open_candidates=_d_candidates,
                            right_click_pos=_d_rclick,
                        )
                        _d_ms = int((time.time() - img_start) * 1000)
                        if not _d_paths:
                            try:
                                _fb_path = os.path.join(run_folder, "0_fallback.png")
                                try:
                                    selected_item.capture_as_image().save(_fb_path)
                                except Exception:
                                    moments_window.capture_as_image().save(_fb_path)
                                if os.path.isfile(_fb_path):
                                    _d_paths = [_fb_path]
                                    print("[debug:img:deferred] extraction empty, fallback captured 1 image")
                            except Exception as _fb_empty_err:
                                print(f"[debug:img:deferred] empty-result fallback failed: {_fb_empty_err}")
                        result['image_paths'] = _d_paths
                        print(f'[debug:img:deferred] extracted {len(_d_paths)}/{image_count} images ({_d_ms}ms)')
                        _deferred_images.set(_d_paths)
                    except Exception as _d_err:
                        print(f'[debug:img:deferred] extraction failed: {_d_err}')
                        _fallback_paths = []
                        try:
                            _fb_path = os.path.join(run_folder, "0_fallback.png")
                            try:
                                selected_item.capture_as_image().save(_fb_path)
                            except Exception:
                                moments_window.capture_as_image().save(_fb_path)
                            if os.path.isfile(_fb_path):
                                _fallback_paths.append(_fb_path)
                                result['image_paths'] = _fallback_paths
                                print("[debug:img:deferred] fallback captured 1 image for OCR/AI")
                        except Exception as _fb_err:
                            print(f"[debug:img:deferred] fallback capture failed: {_fb_err}")
                        _deferred_images.set(_fallback_paths)
                else:
                    _deferred_images.set([])

                # Re-acquire anchor after image extraction.
                try:
                    comment_listitem = resolve_feed_comment_anchor(moments_list, selected_item)
                except Exception:
                    pass

            # Batch-first path for Hook mode: collect all answers, then send in one batch.
            if use_hook_batch and _hook_dispatcher is not None:
                if hook_batch_mode == "fast_first_batch":
                    # ============================================================
                    # Fast-First + Batch-Rest Strategy
                    # 1. Wait for first answer (usually OCR, ~300ms)
                    # 2. Post immediately via Hook
                    # 3. Continue collecting remaining answers (timeout 8s)
                    # 4. Batch post remaining in Serial Mode
                    # ============================================================
                    print("[debug:stream] fast_first_batch mode: waiting for first answer")

                    editor_preload_enabled = os.environ.get(
                        "PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD", "0"
                    ).strip().lower() in {"1", "true", "yes", "on"}
                    editor_preload_started = False
                    editor_preload_done = threading.Event()
                    editor_preload_ok = False

                    def _preload_comment_editor_for_fallback() -> None:
                        nonlocal editor_preload_started, editor_preload_ok
                        if editor_preload_started:
                            return
                        if _hook_dispatcher is None or getattr(_hook_dispatcher, "_ui_sender", None) is None:
                            return
                        editor_preload_started = True

                        def _run_preload() -> None:
                            nonlocal editor_preload_ok
                            try:
                                _opened = open_comment_editor(
                                    moments_window,
                                    selected_item,
                                    use_offset_fix=False,
                                    pre_move_coords=center_point,
                                )
                                editor_preload_ok = bool(_opened)
                                if _opened:
                                    print("[debug:stream] editor pre-opened while waiting first answer")
                                else:
                                    print("[debug:stream] editor pre-open failed while waiting first answer")
                            except Exception as _pre_err:
                                print(f"[debug:stream] editor preload error: {_pre_err}")
                            finally:
                                editor_preload_done.set()

                        try:
                            threading.Thread(target=_run_preload, daemon=True).start()
                        except Exception as _thread_err:
                            print(f"[debug:stream] editor preload thread start failed: {_thread_err}")
                            editor_preload_done.set()

                    def _try_send_first_using_preloaded_editor(first_text: str) -> bool | None:
                        if not editor_preload_enabled or not editor_preload_started:
                            return None
                        try:
                            preload_wait_ms = int(
                                os.environ.get(
                                    "PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD_WAIT_MS", "180"
                                )
                            )
                        except Exception:
                            preload_wait_ms = 180
                        if preload_wait_ms < 0:
                            preload_wait_ms = 0
                        if preload_wait_ms > 1200:
                            preload_wait_ms = 1200
                        try:
                            preload_grace_ms = int(
                                os.environ.get(
                                    "PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD_GRACE_MS", "0"
                                )
                            )
                        except Exception:
                            preload_grace_ms = 0
                        if preload_grace_ms < 0:
                            preload_grace_ms = 0
                        if preload_grace_ms > 1200:
                            preload_grace_ms = 1200

                        if not editor_preload_done.wait(preload_wait_ms / 1000.0):
                            # Grace wait avoids immediate fallback/re-open churn when the
                            # preloader is just about to expose the editor.
                            if preload_grace_ms > 0 and wait_comment_editor_state(
                                moments_window,
                                opened=True,
                                timeout=preload_grace_ms / 1000.0,
                                poll=0.04,
                            ):
                                print(
                                    f"[debug:stream] editor preload became visible during "
                                    f"grace wait ({preload_grace_ms}ms)"
                                )
                            else:
                                print(
                                    f"[debug:stream] editor preload pending after {preload_wait_ms}ms, "
                                    "falling back to normal UI flow"
                                )
                                return None
                        if not editor_preload_ok:
                            # In race windows the preload thread may still be finalizing
                            # while editor is already visible; trust UI state if present.
                            if not wait_comment_editor_state(
                                moments_window, opened=True, timeout=0.08, poll=0.04
                            ):
                                print("[debug:stream] editor preload not ready, falling back to normal UI flow")
                                return None
                            print("[debug:stream] editor visible despite pending preload flag, continue with preloaded UI")
                        if not wait_comment_editor_state(
                            moments_window, opened=True, timeout=0.12, poll=0.04
                        ):
                            print("[debug:stream] preloaded editor missing, falling back to normal UI flow")
                            return None

                        posted = paste_and_send_comment(
                            moments_window,
                            first_text,
                            anchor_mode="list",
                            anchor_source=comment_listitem,
                            clear_first=False,
                            skip_editor_check=True,
                        )
                        if posted:
                            print(f"[debug:stream] first comment posted via ui(preloaded): {first_text}")
                        else:
                            print("[debug:stream] ui(preloaded) send failed, will retry normal UI flow")
                        return bool(posted)

                    def _refresh_first_ui_anchor() -> None:
                        nonlocal selected_item, comment_listitem, moments_list, center_point
                        try:
                            _fresh_list = reacquire_feed_list(retries=4, wait=0.08)
                            if _fresh_list is not None:
                                moments_list = _fresh_list
                                _focused = [
                                    li
                                    for li in moments_list.children(control_type='ListItem')
                                    if li.has_keyboard_focus()
                                ]
                                if _focused:
                                    try:
                                        _cls = _focused[0].class_name()
                                    except Exception:
                                        _cls = ""
                                    if _cls and ("TimelineCommentCell" not in _cls):
                                        selected_item = _focused[0]
                                if selected_item is not None:
                                    try:
                                        comment_listitem = resolve_feed_comment_anchor(
                                            moments_list, selected_item
                                        )
                                    except Exception:
                                        comment_listitem = None
                                    try:
                                        center_point = compute_feed_item_center_point(selected_item)
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                    def _is_ui_com_unstable(error_message: str) -> bool:
                        _msg = str(error_message or "")
                        if not _msg:
                            return False
                        _msg_l = _msg.lower()
                        return (
                            "-2147220991" in _msg
                            or "事件无法调用任何订户" in _msg
                            or "no subscribers" in _msg_l
                        )

                    def _send_first_via_ui_with_retry(first_text: str) -> tuple[bool, bool, bool]:
                        """Return (posted, used_preloaded_path, ui_com_unstable)."""
                        preloaded_posted = _try_send_first_using_preloaded_editor(first_text)
                        if preloaded_posted is True:
                            return True, True, False

                        try:
                            from .comment_dispatcher import UICommentSender
                        except Exception as _import_err:
                            print(f"[debug:stream] UICommentSender import failed: {_import_err}")
                            return False, False, False

                        def _send_once(tag: str) -> tuple[bool, bool]:
                            try:
                                ui_sender = UICommentSender(
                                    moments_window,
                                    selected_item,
                                    anchor_mode="list",
                                    anchor_source=comment_listitem,
                                    pre_move_coords=center_point,
                                )
                                ui_result = ui_sender.send_comment(
                                    first_text,
                                    author=result.get("author", ""),
                                    content_hash=result.get("fingerprint", "")[:16],
                                )
                                if ui_result.success:
                                    print(
                                        f"[debug:stream] first comment posted via ui({tag}) "
                                        f"latency={ui_result.latency_ms}ms: {first_text}"
                                    )
                                    return True, False
                                _ui_com_unstable = _is_ui_com_unstable(ui_result.error_message)
                                print(
                                    f"[debug:stream] ui({tag}) first send failed: "
                                    f"{ui_result.error_message or 'unknown'}"
                                )
                                return False, _ui_com_unstable
                            except Exception as _ui_exc:
                                print(f"[debug:stream] ui({tag}) first send exception: {_ui_exc}")
                                return False, _is_ui_com_unstable(str(_ui_exc))

                        ui_com_unstable = False

                        _ok, _com_unstable = _send_once("sender")
                        ui_com_unstable = ui_com_unstable or _com_unstable
                        if _ok:
                            return True, False, ui_com_unstable

                        # One extra recovery attempt with a fresh list item/anchor.
                        _refresh_first_ui_anchor()
                        _ok, _com_unstable = _send_once("sender+refresh")
                        ui_com_unstable = ui_com_unstable or _com_unstable
                        if _ok:
                            return True, False, ui_com_unstable
                        return False, False, ui_com_unstable

                    if editor_preload_enabled:
                        _preload_comment_editor_for_fallback()
                    else:
                        print("[debug:stream] fast_first editor preload disabled")
                    
                    first_answer = None
                    pending_first_answer = None
                    early_scatter_sent: set[str] = set()
                    if first_comment_done:
                        print("[debug:stream] first answer already sent pre-image, skipping wait")
                        first_answer = instant_first_answer
                        posted_any = True
                        comment_count = 1
                        if first_answer:
                            all_answers.append(first_answer)
                    else:
                        first_answer = None
                        first_start = time.time()
                        try:
                            first_answer_wait_s = float(
                                os.environ.get(
                                    "PYWEIXIN_FAST_FIRST_FIRST_ANSWER_TIMEOUT_S",
                                    "2.0",
                                )
                            )
                        except Exception:
                            first_answer_wait_s = 2.0
                        if first_answer_mode_early == "ai_ocr_only" and first_answer_wait_s < 4.0:
                            first_answer_wait_s = 6.0
                        if first_answer_wait_s < 0.5:
                            first_answer_wait_s = 0.5
                        if first_answer_wait_s > 20.0:
                            first_answer_wait_s = 20.0
                        try:
                            first_answer = answer_queue.get(timeout=first_answer_wait_s)
                            first_elapsed = int((time.time() - first_start) * 1000)
                            print(f"[debug:stream] first answer ready ({first_elapsed}ms): {first_answer}")
                        except _queue_mod.Empty:
                            print(
                                f"[debug:stream] first answer timeout "
                                f"({first_answer_wait_s:.2f}s), fallback to batch"
                            )

                        posted_any = False

                        # Post first answer immediately
                        if first_answer:
                            first_answer = str(first_answer).strip()
                            if first_answer:
                                try:
                                    # Fast-first baseline: send first comment via UI directly
                                    # to avoid hook probing noise/race on unstable capture state.
                                    first_ui_ok = False
                                    ui_com_unstable = False
                                    first_ui_ok, preloaded_path, ui_com_unstable = _send_first_via_ui_with_retry(first_answer)
                                    posted_any = bool(first_ui_ok)
                                    comment_count = 1 if posted_any else 0

                                    if first_ui_ok:
                                        all_answers.append(first_answer)
                                        if not preloaded_path:
                                            print(f"[debug:stream] first comment posted via ui: {first_answer}")
                                    else:
                                        if ui_com_unstable:
                                            pending_first_answer = first_answer
                                            result['ai_answer'] = first_answer
                                            result['comment_posted'] = False
                                            if not result.get('error'):
                                                result['error'] = 'ui com unstable, retry next poll'
                                            print(
                                                "[debug:stream] ui COM unstable on first send, "
                                                "skip slow fallback and retry in next poll"
                                            )
                                            return result
                                        print("[debug:stream] first comment UI failed, trying hook fallback once")
                                        first_result = _hook_dispatcher.post_comment(
                                            first_answer,
                                            author=result.get("author", ""),
                                            content_hash=result.get("fingerprint", "")[:16],
                                        )
                                        posted_any = first_result.success
                                        comment_count = 1 if first_result.success else 0
                                        if first_result.success:
                                            all_answers.append(first_answer)
                                            print(
                                                f"[debug:stream] first comment recovered via "
                                                f"{first_result.method}: {first_answer}"
                                            )
                                        else:
                                            pending_first_answer = first_answer
                                            print(
                                                f"[debug:stream] first comment still failed "
                                                f"({first_result.error_message}), "
                                                "will include it in batch fallback"
                                            )

                                except Exception as exc:
                                    print(f"[debug:stream] first comment exception: {exc}")
                                    pending_first_answer = first_answer

                    def _build_scatter_candidates(answer_text: str) -> list[str]:
                        if not answer_text:
                            return []
                        m = re.match(r"^\s*(\d+)\s*(.+?)\s*$", str(answer_text))
                        if not m:
                            return []
                        base_num = int(m.group(1))
                        keyword = m.group(2).strip()
                        if not keyword:
                            return []

                        raw_vals = os.environ.get(
                            "PYWEIXIN_FAST_FIRST_SCATTER_VALUES", "1,2,3"
                        )
                        nums: list[int] = []
                        seen_num: set[int] = set()
                        for tok in raw_vals.replace("，", ",").split(","):
                            tok = tok.strip()
                            if not tok:
                                continue
                            try:
                                n = int(tok)
                            except Exception:
                                continue
                            if n <= 0 or n in seen_num:
                                continue
                            seen_num.add(n)
                            nums.append(n)

                        if not nums:
                            return []

                        candidates: list[str] = []
                        seen_ans: set[str] = set()
                        for n in nums:
                            if n == base_num:
                                continue
                            ans = f"{n}{keyword}".strip()
                            if not ans or ans == answer_text or ans in seen_ans:
                                continue
                            seen_ans.add(ans)
                            candidates.append(ans)
                        return candidates

                    def _post_early_hook_scatter(answer_text: str) -> None:
                        nonlocal posted_any, comment_count
                        enabled = os.environ.get(
                            "PYWEIXIN_FAST_FIRST_SCATTER", "0"
                        ).strip().lower() in {"1", "true", "yes", "on"}
                        if not enabled:
                            return
                        if not answer_text:
                            return
                        if _hook_dispatcher is None or getattr(_hook_dispatcher, "_hook_sender", None) is None:
                            print("[debug:stream] early scatter skipped: hook sender unavailable")
                            return

                        candidates = _build_scatter_candidates(answer_text)
                        if not candidates:
                            print("[debug:stream] early scatter skipped: no candidates")
                            return

                        try:
                            scatter_max = int(
                                os.environ.get("PYWEIXIN_FAST_FIRST_SCATTER_MAX", "3")
                            )
                        except Exception:
                            scatter_max = 3
                        if scatter_max < 1:
                            scatter_max = 1
                        candidates = candidates[:scatter_max]

                        try:
                            scatter_age_limit_ms = int(
                                os.environ.get("PYWEIXIN_FAST_FIRST_SCATTER_CAPTURE_MAX_AGE_MS", "3000")
                            )
                        except Exception:
                            scatter_age_limit_ms = 3000
                        if scatter_age_limit_ms < 200:
                            scatter_age_limit_ms = 200

                        scatter_strategy = os.environ.get(
                            "PYWEIXIN_FAST_FIRST_SCATTER_STRATEGY", "dispatcher_serial"
                        ).strip().lower()
                        if scatter_strategy not in {"dispatcher_serial", "direct_capture"}:
                            scatter_strategy = "dispatcher_serial"
                        stop_on_fail = os.environ.get(
                            "PYWEIXIN_FAST_FIRST_SCATTER_STOP_ON_FAIL", "1"
                        ).strip().lower() in {"1", "true", "yes", "on"}

                        if scatter_strategy == "dispatcher_serial":
                            try:
                                scatter_gap_ms = int(
                                    os.environ.get("PYWEIXIN_FAST_FIRST_SCATTER_GAP_MS", "90")
                                )
                            except Exception:
                                scatter_gap_ms = 90
                            if scatter_gap_ms < 0:
                                scatter_gap_ms = 0
                            if scatter_gap_ms > 1200:
                                scatter_gap_ms = 1200
                            print(
                                f"[debug:stream] early hook scatter candidates: {candidates} "
                                f"(strategy=dispatcher_serial, gap={scatter_gap_ms}ms)"
                            )
                            try:
                                scatter_hook_wait_ms = int(
                                    os.environ.get("PYWEIXIN_FAST_FIRST_SCATTER_HOOK_WAIT_MS", "650")
                                )
                            except Exception:
                                scatter_hook_wait_ms = 650
                            if scatter_hook_wait_ms < 200:
                                scatter_hook_wait_ms = 200
                            if scatter_hook_wait_ms > 5000:
                                scatter_hook_wait_ms = 5000
                            hook_wait_old = None
                            hook_sender_local = getattr(_hook_dispatcher, "_hook_sender", None)
                            if hook_sender_local is not None:
                                try:
                                    hook_wait_old = int(getattr(hook_sender_local, "_wait_timeout_ms", 400))
                                except Exception:
                                    hook_wait_old = None
                                try:
                                    hook_sender_local._wait_timeout_ms = scatter_hook_wait_ms
                                except Exception:
                                    pass
                            fail_count = 0
                            scatter_use_ui_fallback = os.environ.get(
                                "PYWEIXIN_FAST_FIRST_SCATTER_UI_FALLBACK", "0"
                            ).strip().lower() in {"1", "true", "yes", "on"}
                            scatter_sns_id = ""
                            if hook_sender_local is not None:
                                try:
                                    _latest = hook_sender_local.bridge.get_latest_sns_id()
                                    if _latest.ok:
                                        scatter_sns_id = str(_latest.data.get("sns_id", "") or "")
                                except Exception:
                                    scatter_sns_id = ""
                            try:
                                for scatter_ans in candidates:
                                    try:
                                        if (not scatter_use_ui_fallback) and hook_sender_local is not None:
                                            scatter_res = hook_sender_local.send_comment(
                                                scatter_ans,
                                                sns_id=scatter_sns_id,
                                                author=result.get("author", ""),
                                                content_hash=result.get("fingerprint", "")[:16],
                                            )
                                        else:
                                            scatter_res = _hook_dispatcher.post_comment(
                                                scatter_ans,
                                                author=result.get("author", ""),
                                                content_hash=result.get("fingerprint", "")[:16],
                                            )
                                    except Exception as _send_err:
                                        scatter_res = None
                                        fail_count += 1
                                        print(f"[debug:stream] early scatter exception: {scatter_ans} -> {_send_err}")
                                        if stop_on_fail and fail_count >= 1:
                                            break
                                        if scatter_gap_ms > 0:
                                            time.sleep(scatter_gap_ms / 1000.0)
                                        continue

                                    if scatter_res is not None and scatter_res.success:
                                        if scatter_ans not in early_scatter_sent:
                                            early_scatter_sent.add(scatter_ans)
                                            all_answers.append(scatter_ans)
                                            posted_any = True
                                            comment_count += 1
                                            print(
                                                f"[debug:stream] early scatter posted via "
                                                f"{scatter_res.method}: {scatter_ans}"
                                            )
                                    else:
                                        fail_count += 1
                                        _err = scatter_res.error_message if scatter_res is not None else "unknown"
                                        print(f"[debug:stream] early scatter failed: {scatter_ans} ({_err})")
                                        if stop_on_fail and fail_count >= 1:
                                            break
                                    if scatter_gap_ms > 0:
                                        time.sleep(scatter_gap_ms / 1000.0)
                            finally:
                                if hook_sender_local is not None and hook_wait_old is not None:
                                    try:
                                        hook_sender_local._wait_timeout_ms = hook_wait_old
                                    except Exception:
                                        pass
                            return

                        hook_sender = _hook_dispatcher._hook_sender
                        bridge = hook_sender.bridge
                        try:
                            settle_ms = int(
                                os.environ.get("PYWEIXIN_FAST_FIRST_SCATTER_SETTLE_MS", "140")
                            )
                        except Exception:
                            settle_ms = 140
                        if settle_ms > 0:
                            time.sleep(min(settle_ms, 1200) / 1000.0)
                        try:
                            _st = bridge.status()
                            _age = int(_st.data.get("capture_age_ms", 999999)) if _st.ok else 999999
                            _captured = bool(_st.data.get("state_captured", False)) if _st.ok else False
                            _tid = int(_st.data.get("capture_thread_id", 0)) if _st.ok else 0
                            _arg1_ready = bool(_st.data.get("arg1_template_ready", False)) if _st.ok else False
                            if (not _captured) or (_tid <= 0) or (_age > scatter_age_limit_ms) or (not _arg1_ready):
                                print(
                                    "[debug:stream] early scatter skipped: capture not fresh "
                                    f"(age={_age}ms, captured={_captured}, tid={_tid}, arg1_ready={_arg1_ready})"
                                )
                                return
                        except Exception as _st_err:
                            print(f"[debug:stream] early scatter status check failed: {_st_err}")
                            return

                        scatter_sns_id = ""
                        try:
                            _sns = bridge.get_latest_sns_id()
                            if _sns.ok:
                                scatter_sns_id = str(_sns.data.get("sns_id", "") or "")
                        except Exception:
                            scatter_sns_id = ""
                        if not scatter_sns_id:
                            print("[debug:stream] early scatter skipped: sns_id unavailable")
                            return

                        scatter_mode = os.environ.get(
                            "PYWEIXIN_FAST_FIRST_SCATTER_MODE", "capture_thread"
                        ).strip().lower()
                        if scatter_mode not in {"capture_thread", "pipe_thread"}:
                            scatter_mode = "capture_thread"
                        try:
                            scatter_wait_ms = int(
                                os.environ.get("PYWEIXIN_FAST_FIRST_SCATTER_WAIT_MS", "650")
                            )
                        except Exception:
                            scatter_wait_ms = 650
                        if scatter_wait_ms < 200:
                            scatter_wait_ms = 200
                        if scatter_wait_ms > 5000:
                            scatter_wait_ms = 5000

                        print(
                            f"[debug:stream] early hook scatter candidates: {candidates} "
                            f"(mode={scatter_mode}, wait={scatter_wait_ms}ms)"
                        )
                        fail_count = 0
                        for scatter_ans in candidates:
                            try:
                                # Scatter path intentionally avoids capture->pipe auto-retry to
                                # prevent SEH regressions from direct call fallback.
                                scatter_resp = bridge.send_comment(
                                    scatter_ans,
                                    sns_id=scatter_sns_id,
                                    reply_to="",
                                    allow_queue_fallback=False,
                                    execution_mode=scatter_mode,
                                    wait_timeout_ms=scatter_wait_ms,
                                    prefer_arg1_template=True,
                                )
                            except Exception as _send_err:
                                scatter_resp = None
                                fail_count += 1
                                print(f"[debug:stream] early scatter exception: {scatter_ans} -> {_send_err}")
                                if stop_on_fail and fail_count >= 1:
                                    break
                                continue

                            if scatter_resp is not None and scatter_resp.ok:
                                if scatter_ans not in early_scatter_sent:
                                    early_scatter_sent.add(scatter_ans)
                                    all_answers.append(scatter_ans)
                                    posted_any = True
                                    comment_count += 1
                                    print(
                                        f"[debug:stream] early scatter posted via "
                                        f"{scatter_mode}: {scatter_ans}"
                                    )
                            else:
                                fail_count += 1
                                _err = scatter_resp.error_message if scatter_resp is not None else "unknown"
                                print(f"[debug:stream] early scatter failed: {scatter_ans} ({_err})")
                                if stop_on_fail and fail_count >= 1:
                                    break

                    # In fast_first_batch path, we still must release deferred images
                    # after first comment so OCR/AI can continue producing answers.
                    if comment_count >= 1 or bool(first_answer):
                        _extract_deferred_images_after_first_comment()
                    if comment_count >= 1 and first_answer:
                        _post_early_hook_scatter(str(first_answer).strip())

                    # Collect remaining answers with optional incremental flush.
                    remaining = []
                    collect_start = time.time()
                    try:
                        max_collect_time = float(
                            os.environ.get("PYWEIXIN_FAST_FIRST_COLLECT_TIMEOUT_S", "12")
                        )
                    except Exception:
                        max_collect_time = 12.0
                    if max_collect_time < 2.0:
                        max_collect_time = 2.0
                    if max_collect_time > 60.0:
                        max_collect_time = 60.0

                    try:
                        batch_concurrency = int(
                            os.environ.get("PYWEIXIN_HOOK_MAX_CONCURRENCY", "1")
                        )
                    except Exception:
                        batch_concurrency = 1
                    if batch_concurrency < 1:
                        batch_concurrency = 1

                    try_parallel_remaining = os.environ.get(
                        "PYWEIXIN_FAST_FIRST_TRY_PARALLEL_REMAINING", "1"
                    ) in {"1", "true", "True", "yes", "on"}
                    prefer_parallel_remaining = os.environ.get(
                        "PYWEIXIN_FAST_FIRST_PREFER_PARALLEL_REMAINING", "0"
                    ) in {"1", "true", "True", "yes", "on"}
                    try:
                        parallel_min_remaining = int(
                            os.environ.get("PYWEIXIN_FAST_FIRST_PARALLEL_MIN_REMAINING", "3")
                        )
                    except Exception:
                        parallel_min_remaining = 3
                    if parallel_min_remaining < 1:
                        parallel_min_remaining = 1
                    parallel_ready = False
                    if try_parallel_remaining:
                        try:
                            if (
                                _hook_dispatcher is not None
                                and _hook_dispatcher._hook_sender is not None
                            ):
                                parallel_ready = _hook_dispatcher._hook_sender.is_parallel_ready()
                        except Exception:
                            parallel_ready = False

                    def _resolve_remaining_batch_mode(batch_size: int) -> tuple[str, bool]:
                        use_parallel = (
                            parallel_ready
                            and prefer_parallel_remaining
                            and batch_size >= parallel_min_remaining
                        )
                        return ("parallel", True) if use_parallel else ("piggyback", False)

                    if parallel_ready and prefer_parallel_remaining:
                        print(
                            "[debug:stream] fast_first_batch: remaining comments use parallel when "
                            f"batch>={parallel_min_remaining}"
                        )
                    elif parallel_ready and not prefer_parallel_remaining:
                        print(
                            "[debug:stream] fast_first_batch: remaining comments -> piggyback "
                            "(parallel ready but disabled by policy)"
                        )
                    elif not parallel_ready and try_parallel_remaining:
                        print(
                            "[debug:stream] fast_first_batch: remaining comments -> piggyback "
                            "(parallel not ready)"
                        )
                    else:
                        print(
                            "[debug:stream] fast_first_batch: remaining comments -> piggyback "
                            "(parallel disabled)"
                        )

                    flush_early = os.environ.get(
                        "PYWEIXIN_FAST_FIRST_FLUSH_EARLY", "0"
                    ).strip().lower() in {"1", "true", "yes", "on"}
                    try:
                        flush_min_ready = int(
                            os.environ.get("PYWEIXIN_FAST_FIRST_FLUSH_MIN_READY", "1")
                        )
                    except Exception:
                        flush_min_ready = 1
                    if flush_min_ready < 1:
                        flush_min_ready = 1

                    def _refresh_ui_sender_anchor_before_batch() -> None:
                        nonlocal selected_item, comment_listitem, moments_list, center_point
                        try:
                            # Force refresh before remaining batch posting:
                            # focused listitem/anchor may become stale after first comment + waits.
                            try:
                                _fresh_list = reacquire_feed_list(retries=4, wait=0.08)
                                if _fresh_list is not None:
                                    moments_list = _fresh_list
                                    _focused = [
                                        li
                                        for li in moments_list.children(control_type='ListItem')
                                        if li.has_keyboard_focus()
                                    ]
                                    if _focused and _focused[0].class_name() not in not_contents:
                                        selected_item = _focused[0]
                                    if selected_item is not None:
                                        try:
                                            comment_listitem = resolve_feed_comment_anchor(
                                                moments_list, selected_item
                                            )
                                        except Exception:
                                            comment_listitem = None
                                        try:
                                            center_point = compute_feed_item_center_point(selected_item)
                                        except Exception:
                                            pass
                            except Exception:
                                pass

                            if _hook_dispatcher is not None and getattr(_hook_dispatcher, "_ui_sender", None) is not None:
                                _hook_dispatcher._ui_sender._content_item = selected_item
                                _hook_dispatcher._ui_sender._pre_move_coords = center_point
                                try:
                                    _cr = comment_listitem.rectangle() if comment_listitem is not None else None
                                    if _cr is not None and _is_valid_anchor_rect(_cr):
                                        _hook_dispatcher._ui_sender._anchor_source = comment_listitem
                                    else:
                                        _hook_dispatcher._ui_sender._anchor_source = None
                                except Exception:
                                    _hook_dispatcher._ui_sender._anchor_source = None
                        except Exception:
                            pass

                    def _post_remaining_batch(batch_answers: list[str], reason: str) -> int:
                        nonlocal posted_any, comment_count
                        if not batch_answers:
                            return 0
                        try:
                            batch_mode_override, parallel_send_all = _resolve_remaining_batch_mode(
                                len(batch_answers)
                            )
                            _refresh_ui_sender_anchor_before_batch()
                            batch_result = _hook_dispatcher.post_batch_comments(
                                batch_answers,
                                author=result.get("author", ""),
                                content_hash=result.get("fingerprint", "")[:16],
                                concurrency=batch_concurrency,
                                batch_mode_override=batch_mode_override,
                                parallel_send_all=parallel_send_all,
                            )
                            posted_batch_answers: list[str] = []
                            for _idx, _ans in enumerate(batch_answers):
                                if _idx < len(batch_result.results) and batch_result.results[_idx].success:
                                    posted_batch_answers.append(_ans)
                            all_answers.extend(posted_batch_answers)
                            posted_any = posted_any or (batch_result.succeeded > 0)
                            comment_count += batch_result.succeeded
                            print(
                                f"[debug:stream] {reason} posted: "
                                f"{batch_result.succeeded}/{batch_result.total} "
                                f"(accepted={posted_batch_answers})"
                            )
                            return int(batch_result.succeeded)
                        except Exception as exc:
                            print(f"[debug:stream] {reason} exception: {exc}")
                            return 0

                    if pending_first_answer and pending_first_answer not in remaining:
                        remaining.append(pending_first_answer)
                        print(
                            f"[debug:stream] prepended pending first answer: "
                            f"{pending_first_answer}"
                        )

                    print("[debug:stream] collecting remaining answers...")
                    post_first_remaining_early = os.environ.get(
                        "PYWEIXIN_FAST_FIRST_POST_FIRST_REMAINING_EARLY", "0"
                    ).strip().lower() in {"1", "true", "yes", "on"}
                    post_first_remaining_done = False
                    while len(remaining) < 10:
                        timeout = max(0.1, max_collect_time - (time.time() - collect_start))
                        if timeout <= 0:
                            print("[debug:stream] collect timeout reached")
                            break

                        try:
                            answer = answer_queue.get(timeout=timeout)
                            if answer is None:
                                print("[debug:stream] sentinel received, all answers collected")
                                break

                            answer = str(answer).strip()
                            if answer and answer in early_scatter_sent:
                                print(f"[debug:stream] skip already-scattered answer: {answer}")
                                continue
                            if answer and not (comment_count >= 1 and answer == first_answer):
                                remaining.append(answer)
                                print(f"[debug:stream] queued: {answer}")
                                if post_first_remaining_early and (not post_first_remaining_done) and remaining:
                                    _early_answer = remaining[0]
                                    _succ = _post_remaining_batch([_early_answer], "early one-shot")
                                    if _succ > 0:
                                        remaining = remaining[1:]
                                    post_first_remaining_done = True
                                if flush_early and len(remaining) >= flush_min_ready:
                                    _post_remaining_batch(remaining[:], "incremental batch")
                                    remaining.clear()

                        except _queue_mod.Empty:
                            print("[debug:stream] no more answers in queue")
                            break

                    if remaining:
                        print(f"[debug:stream] final batch posting {len(remaining)} remaining comments")
                        _post_remaining_batch(remaining[:], "final batch")
                        remaining.clear()
                elif hook_batch_mode in {"piggyback", "parallel", "serial"}:
                    # Original batch mode logic
                    print(f"[debug:stream] hook batch mode={hook_batch_mode}, collecting answers")
                    while True:
                        try:
                            answer = answer_queue.get(timeout=15)
                        except _queue_mod.Empty:
                            print("[debug:stream] queue timeout, stopping")
                            break
                        if answer is None:
                            print("[debug:stream] sentinel received, all answers processed")
                            break
                        answer = str(answer).strip()
                        if not answer:
                            continue
                        all_answers.append(answer)

                    comment_count = len(all_answers)
                    if all_answers:
                        try:
                            try:
                                batch_concurrency = int(
                                    os.environ.get("PYWEIXIN_HOOK_MAX_CONCURRENCY", "10")
                                )
                            except ValueError:
                                batch_concurrency = 10
                            if batch_concurrency < 1:
                                batch_concurrency = 1
                            if batch_concurrency > 20:
                                batch_concurrency = 20

                            batch_result = _hook_dispatcher.post_batch_comments(
                                all_answers,
                                author="",
                                content_hash=result.get("fingerprint", ""),
                                concurrency=batch_concurrency,
                            )
                            posted_any = batch_result.succeeded > 0
                            print(
                                f"[debug:stream] batch done: {batch_result.succeeded}/"
                                f"{batch_result.total} in {batch_result.total_latency_ms}ms"
                            )
                            if batch_result.failed > 0 and not result.get('error'):
                                result['error'] = (
                                    f"hook batch partial failure: "
                                    f"{batch_result.failed}/{batch_result.total}"
                                )
                        except Exception as e:
                            print(f"[debug:stream] hook batch error: {e}")
            else:
                # Original streaming path: post each answer immediately.
                editor_preloaded = False
                if not _use_hook:
                    try:
                        editor_preloaded = open_comment_editor(
                            moments_window, selected_item,
                            use_offset_fix=False, pre_move_coords=center_point
                        )
                        if editor_preloaded:
                            print("[debug:stream] editor pre-opened while waiting for answers")
                        else:
                            print("[debug:stream] editor pre-open failed, will retry per comment")
                    except Exception as e:
                        print(f"[debug:stream] editor pre-open error: {e}")
                while True:
                    try:
                        answer = answer_queue.get(timeout=15)
                    except _queue_mod.Empty:
                        print("[debug:stream] queue timeout, stopping")
                        break
                    if answer is None:
                        print("[debug:stream] sentinel received, all answers processed")
                        break
                    answer = str(answer).strip()
                    if not answer:
                        continue
                    all_answers.append(answer)
                    comment_count += 1
                    print(f"[debug:stream] posting comment #{comment_count}: {answer!r}")
                    posted = False
                    # Hook path
                    if _use_hook and _hook_dispatcher is not None:
                        hook_result = _hook_dispatcher.post_comment(
                            answer, author="",
                            content_hash=result.get("fingerprint", ""))
                        posted = hook_result.success
                        if not posted:
                            print(f"[debug:stream] hook failed, falling back to UI")
                            _use_hook = False
                    # UI fallback path
                    if not posted:
                        if comment_count == 1 and editor_preloaded:
                            posted = paste_and_send_comment(
                                moments_window, answer,
                                anchor_mode="list", anchor_source=comment_listitem,
                                clear_first=False, skip_editor_check=True
                            )
                        else:
                            if comment_count > 1:
                                try:
                                    comment_listitem = resolve_feed_comment_anchor(moments_list, selected_item)
                                except Exception:
                                    pass
                            posted = comment_flow(
                                moments_window, selected_item, [answer],
                                anchor_mode="list", anchor_source=comment_listitem,
                                use_offset_fix=False, clear_first=False,
                                pre_move_coords=center_point
                            )
                    if posted:
                        posted_any = True
                        print(f"[debug:stream] comment #{comment_count} posted OK")
                        # UI 评论会触发 hook callback 刷新 capture，重新检查 Hook
                        if not _use_hook and _hook_dispatcher is not None:
                            try:
                                time.sleep(0.1)  # 等 hook callback 完成
                                if _hook_dispatcher._hook_sender and _hook_dispatcher._hook_sender.is_hook_ready():
                                    _st = _hook_dispatcher._hook_sender._bridge.status()
                                    _age = _st.data.get("capture_age_ms", 0) if _st.ok else 99999
                                    if _age < 5_000:
                                        _use_hook = True
                                        print(f"[debug:stream] hook re-enabled after UI comment (capture_age={_age}ms)")
                            except Exception:
                                pass
                    else:
                        print(f"[debug:stream] comment #{comment_count} post FAILED")

                    if comment_count == 1:
                        _extract_deferred_images_after_first_comment()

            # 安全兜底：如果延迟提取标记仍为 True（循环未触发提取），释放 OCR/AI
            if _defer_image_extraction:
                print("[debug:img:deferred] fallback: loop ended without extraction, releasing OCR/AI")
                _deferred_images.set([])

            total_ms = int((time.time() - parallel_start) * 1000)
            print(f'[debug:main] streaming done: {comment_count} comments, {total_ms}ms total')
            result['ai_answer'] = all_answers if len(all_answers) != 1 else all_answers[0]
            result['comment_posted'] = posted_any
            if not posted_any and not result.get('error'):
                result['error'] = 'comment flow finished but send was not verified'
        else:
            ai_answer = cb_result
            print(f'[debug:main] batch mode, ai_callback returned: {ai_answer!r}')
            result['ai_answer'] = ai_answer
            if isinstance(ai_answer, list):
                answer_list = [a.strip() for a in ai_answer if isinstance(a, str) and a.strip()]
            elif isinstance(ai_answer, str) and ai_answer.strip():
                answer_list = [ai_answer.strip()]
            else:
                answer_list = []
            if not answer_list:
                return result
            result['comment_attempted'] = True
            print(f'[debug:comment] calling comment_flow with answers={answer_list}')
            posted = comment_flow(
                moments_window, selected_item, answer_list,
                anchor_mode='list', anchor_source=comment_listitem,
                use_offset_fix=False, clear_first=False,
                pre_move_coords=center_point
            )
            result['comment_posted'] = posted
            if not posted and not result.get('error'):
                result['error'] = 'comment flow finished but send was not verified'

        return result

    except Exception as e:
        result['error'] = str(e)
        if result.get('ai_answer') and not result.get('comment_attempted'):
            result['success'] = False
        import traceback
        traceback.print_exc()
        return result
    finally:
        if created_window and moments_window is not None and close_weixin:
            try:
                moments_window.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# rush_engine 兼容接口
# ---------------------------------------------------------------------------

def get_latest_friend_moment(friend: str, target_folder: str = None, is_maximize: bool = None,
                              close_weixin: bool = None, **kwargs) -> dict | None:
    """供 rush_engine.fetch_latest_post 调用。
    打开好友朋友圈，抓取第一条帖子内容（不评论），返回 dict。"""
    def _noop_callback(content, image_paths):
        return None

    result = fetch_and_comment_friend_moment(
        friend=friend,
        ai_callback=_noop_callback,
        target_folder=target_folder,
        is_maximize=is_maximize,
        close_weixin=close_weixin,
    )
    if not result or not result.get('success'):
        return None
    return {
        '内容': result.get('content', ''),
        '发布时间': result.get('publish_time', ''),
        '图片数量': result.get('image_count', 0),
        'image_paths': result.get('image_paths', []),
        'screenshot_path': result.get('screenshot_path', ''),
        'fingerprint': result.get('fingerprint', ''),
        'detail_folder': result.get('detail_folder', ''),
    }


def comment_friend_moment(friend: str, comment_text: str, is_maximize: bool = None,
                           close_weixin: bool = None, **kwargs) -> bool:
    """供 rush_engine.comment_post 调用。
    打开好友朋友圈，在第一条帖子评论。"""
    def _callback(content, image_paths):
        return comment_text

    result = fetch_and_comment_friend_moment(
        friend=friend,
        ai_callback=_callback,
        is_maximize=is_maximize,
        close_weixin=close_weixin,
    )
    return bool(result and result.get('comment_posted'))

