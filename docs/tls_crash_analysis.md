# TLS 崩溃根因分析（并行评论场景）

> WeChat 4.1.7.30 / Weixin.dll x64
> 更新时间：2026-02-10（按最新代码与反汇编结论对齐）

## 1. 问题定义

在非 capture thread（如 pipe thread / worker thread）调用 `g_original_fn`（`cgi_A_caller_2`, RVA `0x049e9240`）时，进程可在 `Weixin.dll + 0x3c5c70` 崩溃：

```text
ACCESS_VIOLATION (read) at 0x0
RIP = Weixin.dll + 0x3c5c70
```

串行 piggyback 可成功，但样本耗时约 `5591ms / 10 条`，与 `<1s` 目标有明显差距。

## 2. 崩溃链路（关键指令）

```text
cgi_A_caller_2
  -> 内部函数 (约 RVA 0x3c5970)
     0x3c597c: mov rdi, rcx                 ; rdi = arg1
     0x3c597f: cmp qword ptr [rdi+0x368], 0 ; 检查 arg1->+0x368
     (为空时调用 0xb91e90)
     0x3c5b67: mov rdi, [rdi+0x368]
     0x3c5c70: mov rax, [rdi]               ; rdi=0 时崩溃
```

## 3. `0xb91e90` 的根因结论

`0xb91e90` 通过隐式 TLS 路径取上下文对象，关键点：

1. 读取 `gs:[0x58]`（TEB `ThreadLocalStoragePointer`）。
2. 通过 Weixin.dll 的 TLS index 取该模块 TLS 数据块。
3. 读取 `tls_data + 0x358` 并检查 bit0。
4. 条件不满足时返回 `NULL`。

当该返回值导致 `arg1->+0x368` 为空，后续在 `0x3c5c70` 解引用即崩溃。

## 4. 已尝试路线与结论

| 路线 | 结果 | 结论 |
|---|---|---|
| 标准 TLS slots 复制（0-63） | 未根治 | 问题不只在标准 TLS |
| FLS 复制 | 未根治 | 问题不只在 FLS |
| 隐式 TLS 整块复制 | 风险高/不稳定 | 会污染线程运行时状态 |
| piggyback 回调内执行 | 可成功发送 | 成功率上来了，但目前速度未达标 |

## 5. 与当前代码的对齐状态

1. `TLS_ACCESSOR_RVA = 0x00b91e90` 已在代码中记录。
2. 当前代码尚未安装 `0xb91e90` 的函数级 hook。
3. 当前主打法是 piggyback + `request->+0x368` 缓存与预填充。
4. hook 回调内并行分支已存在，但稳定收益仍待验收。

## 6. 下一步（仅作为方案，不是已实现状态）

候选方案是对 `0xb91e90` 做定向 hook：仅在并行 worker 上返回 capture-thread 缓存值，普通路径走原函数。该方案目前仍处于分析/设计阶段，尚未合入现代码。

达标前必须验证：

1. 并行 worker 下是否稳定 `10/10`。
2. 是否引入新崩溃或上下文污染。
3. 连续多轮是否可稳定 `<1s`。
