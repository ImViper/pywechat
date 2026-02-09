"""
Viper Moments Extension — 朋友圈自动评论与增强功能。
不修改 upstream 代码，只导入其公共 API。
"""
import os
import re
import time
import json
import hashlib
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


def _build_post_fingerprint(content: str, post_time: str, photo_num: int, video_num: int, item_key) -> str:
    """Build fingerprint for post deduplication."""
    hasher = hashlib.sha1()
    hasher.update((content or '').encode('utf-8', errors='ignore'))
    hasher.update((post_time or '').encode('utf-8', errors='ignore'))
    hasher.update(str(photo_num).encode('utf-8'))
    hasher.update(str(video_num).encode('utf-8'))
    if not (content or post_time):
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
            if anchor_mode == 'list':
                _click_send_button(cr, x_offset=_SNS_SEND_LIST_X_OFFSET, y_offset=_SNS_SEND_LIST_Y_OFFSET)
            else:
                _click_send_button(cr, x_offset=_SNS_SEND_DETAIL_X_OFFSET, y_offset=_SNS_SEND_DETAIL_Y_OFFSET)
            clicked_by_anchor = True
            print('[debug:paste_send] clicked send by anchor')
        except Exception as e:
            clicked_by_anchor = False
            print(f'[debug:paste_send] anchor click failed: {e}')
    if not clicked_by_anchor:
        pyautogui.press('enter')
        print('[debug:paste_send] pressed enter to send')
    closed = wait_comment_editor_state(moments_window, opened=False, timeout=0.4, poll=0.05)
    print(f'[debug:paste_send] editor closed after send={closed}')
    if closed:
        return True
    if clicked_by_anchor:
        pyautogui.press('enter')
        closed2 = wait_comment_editor_state(moments_window, opened=False, timeout=0.3, poll=0.05)
        print(f'[debug:paste_send] fallback enter, editor closed={closed2}')
        if closed2:
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
                pyautogui.press('enter')

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
                pyautogui.press('enter')

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

        hasher = hashlib.sha1()
        hasher.update(content.encode('utf-8', errors='ignore'))
        hasher.update(publish_time.encode('utf-8', errors='ignore'))
        hasher.update(str(image_count).encode('utf-8'))
        result['fingerprint'] = hasher.hexdigest()

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
    moments_window: WindowSpecification = None
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
                selected_item = selected[0]
                break
        if selected_item is None:
            result['error'] = 'cannot locate first valid feed item'
            return result

        author, body, content, image_count, publish_time = parse_feed_listitem(selected_item)
        result['author'] = author
        result['content'] = content
        result['image_count'] = image_count
        result['publish_time'] = publish_time

        hasher = hashlib.sha1()
        hasher.update(content.encode('utf-8', errors='ignore'))
        hasher.update(publish_time.encode('utf-8', errors='ignore'))
        hasher.update(str(image_count).encode('utf-8'))
        result['fingerprint'] = hasher.hexdigest()

        if target_author:
            author_hit = (author == target_author) or (target_author in author)
            if not author_hit:
                result['success'] = True
                return result

        if last_fingerprint and result['fingerprint'] == last_fingerprint:
            result['success'] = True
            return result

        text_for_filter = body if body else content
        if include_keywords and not any(kw in text_for_filter for kw in include_keywords):
            result['success'] = True
            return result
        if exclude_keywords and any(kw in text_for_filter for kw in exclude_keywords):
            result['success'] = True
            return result

        prefix = target_author.strip() if target_author else 'feed'
        run_folder = os.path.join(target_folder, f'{prefix}_{int(time.time() * 1000)}')
        os.makedirs(run_folder, exist_ok=True)
        result['detail_folder'] = run_folder

        if image_count > 0:
            try:
                rect = selected_item.rectangle()
                win_rect = moments_window.rectangle()
                viewer_right_click_pos = (win_rect.mid_point().x, win_rect.mid_point().y)
                open_candidates = [
                    (rect.left + 120, rect.bottom - 90),
                    (rect.left + 220, rect.bottom - 120),
                    (rect.mid_point().x, rect.bottom - 100),
                ]
                opened = False
                for open_pos in open_candidates:
                    try:
                        mouse.click(coords=open_pos)
                        time.sleep(0.08)
                        mouse.right_click(coords=viewer_right_click_pos)
                        copy_menu = moments_window.child_window(**MenuItems.CopyMenuItem)
                        if copy_menu.exists(timeout=0.15):
                            copy_menu.click_input()
                            time.sleep(0.15)
                            first_img_path = os.path.join(run_folder, '0.png')
                            SystemSettings.save_pasted_image(first_img_path)
                            if os.path.isfile(first_img_path):
                                result['image_paths'].append(first_img_path)
                                opened = True
                                for i in range(1, image_count):
                                    pyautogui.press('right', interval=0.08)
                                    time.sleep(0.1)
                                    mouse.right_click(coords=viewer_right_click_pos)
                                    copy_menu = moments_window.child_window(**MenuItems.CopyMenuItem)
                                    if copy_menu.exists(timeout=0.15):
                                        copy_menu.click_input()
                                        time.sleep(0.15)
                                        img_path = os.path.join(run_folder, f'{i}.png')
                                        SystemSettings.save_pasted_image(img_path)
                                        if os.path.isfile(img_path):
                                            result['image_paths'].append(img_path)
                                break
                    finally:
                        pyautogui.press('esc')
                        time.sleep(0.05)
                if (not opened) and image_count > 0:
                    result['error'] = 'list mode cannot extract images, skipped'
                    result['success'] = True
                    return result
            except Exception as e:
                result['error'] = f'list image extraction failed: {e}'
                result['success'] = True
                return result

        result['success'] = True

        import queue as _queue_mod
        print('[debug:main] starting ai_callback + reacquire in parallel')
        parallel_start = time.time()
        cb_result = ai_callback(content, result['image_paths'])
        is_streaming = isinstance(cb_result, _queue_mod.Queue)

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
            # 预开编辑器：在等待 AI/OCR 答案期间先点开评论输入框
            editor_preloaded = False
            try:
                editor_preloaded = open_comment_editor(
                    moments_window, selected_item,
                    use_offset_fix=False, pre_move_coords=center_point
                )
                if editor_preloaded:
                    print('[debug:stream] editor pre-opened while waiting for answers')
                else:
                    print('[debug:stream] editor pre-open failed, will retry per comment')
            except Exception as e:
                print(f'[debug:stream] editor pre-open error: {e}')
            while True:
                try:
                    answer = answer_queue.get(timeout=15)
                except _queue_mod.Empty:
                    print('[debug:stream] queue timeout, stopping')
                    break
                if answer is None:
                    print('[debug:stream] sentinel received, all answers processed')
                    break
                answer = str(answer).strip()
                if not answer:
                    continue
                all_answers.append(answer)
                comment_count += 1
                print(f'[debug:stream] posting comment #{comment_count}: {answer!r}')
                if comment_count == 1 and editor_preloaded:
                    # 编辑器已预开，直接粘贴发送，跳过编辑器检测
                    posted = paste_and_send_comment(
                        moments_window, answer,
                        anchor_mode='list', anchor_source=comment_listitem,
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
                        anchor_mode='list', anchor_source=comment_listitem,
                        use_offset_fix=False, clear_first=False,
                        pre_move_coords=center_point
                    )
                if posted:
                    posted_any = True
                    print(f'[debug:stream] comment #{comment_count} posted OK')
                else:
                    print(f'[debug:stream] comment #{comment_count} post FAILED')

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
