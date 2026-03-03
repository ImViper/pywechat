# 生态调研结论 + 路线 A 实施计划

更新时间：2026-02-12
适用分支：`viper/hook-comment`

---

## 一、生态调研结论

### 1.1 调研目标

调研所有已知微信自动化项目，确认是否有可复用的朋友圈评论实现。

### 1.2 项目逐个分析

#### wxbot (jwping/wxbot)

- **方式**：闭源 sidecar 进程注入 + HTTP REST API
- **微信版本**：3.9.x（不支持 4.0+）
- **朋友圈**：完全不支持，无任何 SNS 相关 API
- **结论**：无参考价值

#### wxhelper (ttttupup/wxhelper)

- **方式**：DLL Hook + HTTP API（port 19088）
- **微信版本**：3.8.x ~ 3.9.x（不支持 4.0+）
- **朋友圈**：只有读取（API 53/54: getSNSFirstPage/getSNSNextPage），无评论/点赞
- **结论**：架构可参考（Hook DLL + HTTP API 模式），但无法用于 4.x 评论

#### WeChatFerry (lich0821/WeChatFerry)

- **方式**：DLL Hook + protobuf IPC，多语言 SDK
- **微信版本**：3.9.11.25
- **朋友圈**：仅 `refresh_pyq(id)` 触发刷新，无评论功能
- **结论**：IPC 设计可参考，但 SNS 评论未涉及

#### lyx102/WeChatHook — 重点分析

- **方式**：闭源 DLL（`wxhook.dll`）+ Python 包装层
- **微信版本**：声称 3.9.5.81 ~ 4.1.1
- **README 声称 82 个功能**，其中 #39~#43 与朋友圈相关：
  - #39: 获取朋友圈首页
  - #40: 获取朋友圈下一页
  - #41: 朋友圈点赞
  - #42: 朋友圈评论
  - #43: 发送朋友圈
- **实际代码验证**：
  - `core.py` 中只实现了 `get_sns_first_page()` 和 `get_sns_next_page()` 两个方法
  - **评论、点赞、发送朋友圈的 API 方法在 Python 源码中不存在**
  - 核心 Hook 逻辑在闭源二进制中：`wxhook.dll`、`start-wechat.exe`、`faker.exe`
  - PyPI 版本 0.0.10（2024-05-12），实际只列出 39 个接口
- **结论**：README 功能列表与实际代码不符。朋友圈评论功能要么在闭源 DLL 中未暴露，要么尚未实现。**不可直接复用**。但其适配 4.1.x 的经验（版本检测、DLL 注入方式）有一定参考价值。

#### RevokeHook (EEEEhex/RevokeHook)

- **方式**：反射 DLL 注入 + PE 头擦除
- **微信版本**：4.0.3.22 ~ 4.0.3.40
- **朋友圈**：不涉及（仅防撤回）
- **结论**：证明 WeChat 4.0 可 Hook。IDA 字符串解密脚本可参考。

#### WeChatSDK.com

- **方式**：协议 + Hook 混合模式（商业闭源）
- **朋友圈**：有明确的评论 API（`moments/replytomomentscomment`）
- **试用**：仍在接受新用户（个人 7 天免费，企业 14 天）
- **结论**：是唯一确认有朋友圈评论 API 的产品，但为付费商业服务。可在路线 A 失败时作为备选评估。

#### iPad 协议 859/861

- **方式**：协议层重放，不需要 PC 客户端
- **朋友圈**：协议层支持
- **价格**：5000+ CNY
- **结论**：工程量等同于造协议客户端，不适合当前目标

#### Citizen Lab MMTLS 研究

- **方式**：Frida Hook 加密模块 → 提取对称密钥 → 离线解密流量
- **平台**：Android WeChat 8.0.x
- **结论**：方法论价值最高。如需理解 `mmsnscomment` 明文协议格式，可尝试将其方法适配到 Windows。作为长期储备（路线 B）。
- **仓库**：`citizenlab/wechat-security-report`

### 1.3 生态总结

| 结论 | 说明 |
|------|------|
| 无开源可复用实现 | 没有任何开源项目实现了 WeChat 4.x Windows 朋友圈评论发送 |
| 我们的实现是独一份 | 已有 piggyback 10/10 成功样本，在整个生态中领先 |
| 纯 HTTP 路线工程量巨大 | 等同于造协议客户端，商业 SDK 卖 5000+ 的就是这个能力 |
| Hook 并行优化是最短路径 | 基础设施已 90% 就绪，只差 TLS 覆盖启用 |

---

## 二、路线决策

### 放弃纯 HTTP 作为冲刺主线

理由：
1. 偏移逐个探测 ROI 过低，`0x74e2b8` 探了多轮仍无 protobuf 字段
2. 即使拿到明文 protobuf，还需实现 MMTLS 加密 + 会话鉴权 + protobuf schema 还原
3. 生态中无人开源过这条路径，商业产品卖数千元
4. 微信版本更新后偏移全部失效

### 回归路线 A：Hook piggyback 并行优化

理由：
1. piggyback 串行已验证 10/10 成功
2. 串行 ~559ms/条，10 并发理论 ~560ms（< 1s）
3. **代码中 TLS accessor hook 和 arg1_ctx_helper hook 已安装，只是 worker 覆盖被注释掉了**
4. 改动范围小、风险可控、可快速验证

### 纯 HTTP / MMTLS 密钥提取作为长期储备（路线 B/C）

不删除已有工具和文档，但不再作为冲刺目标。

---

## 三、路线 A 代码现状分析

### 3.1 已就绪的基础设施

以下代码均在 `hook/src/sns_comment.cpp` 中：

1. **TLS accessor hook 已安装**（第 1778-1796 行）
   - `hooked_tls_accessor()` 已通过 MinHook 安装在 `0xb91e90`
   - 当前行为：capture thread 调用时缓存返回值到 `g_capture_tls_accessor_value`
   - **但 worker 线程调用时直接透传原始函数，不做覆盖**（第 938 行注释）

2. **arg1_ctx_helper hook 已安装**（第 1800-1818 行）
   - `hooked_arg1_ctx_helper()` 在 `0x003c5970`
   - 当 `t_piggyback_parallel_worker == true` 时，用 `g_cached_req_0x368` 填充 `arg1->+0x368`
   - 这个 hook 已经在工作

3. **piggyback 并行分支已实现**（第 1249-1440 行）
   - worker 线程创建、per-worker arg1 模板拷贝、context 填充、SEH 保护
   - `t_piggyback_parallel_worker` 线程局部标记
   - 受 `max_concurrency > 1 && g_cached_req_0x368_valid` 门控

4. **request->+0x368 缓存已实现**（第 1131-1215 行）
   - 在 hook 回调中从 `arg1->+0x368` 或 `request->+0x368` 缓存
   - `g_cached_req_0x368_valid` 标记可用性

5. **隐式 TLS 和 FLS 收集已实现**
   - `collect_capture_implicit_tls()`、`collect_capture_fls()` 在每次 hook 回调中运行

### 3.2 当前瓶颈的精确定位

**`hooked_tls_accessor()` 第 937-956 行**：

```cpp
static void* __fastcall hooked_tls_accessor(int slot) {
    // Do NOT override TLS accessor on worker threads for now.
    // Cross-thread TLS container reuse can cause hangs/crashes.
    if (!g_original_tls_accessor) {
        return nullptr;
    }
    void* value = g_original_tls_accessor(slot);
    // 只在 capture thread 上缓存，不在 worker 上覆盖
    if (value &&
        looks_like_user_pointer(value) &&
        GetCurrentThreadId() == g_capture_thread_id) {
        g_capture_tls_accessor_value = value;
        g_capture_tls_accessor_ready = true;
    }
    return value;
}
```

问题：worker 线程调用 `0xb91e90` 时，原始函数读 `gs:[0x58]`（worker 的 TEB），
该线程没有 Weixin.dll 的 TLS 数据块，返回 NULL → 后续解引用 → crash。

### 3.3 需要的改动

在 `hooked_tls_accessor` 中，当 `t_piggyback_parallel_worker == true` 时，
返回 capture thread 缓存的值而非调用原始函数：

```
伪代码：
if (t_piggyback_parallel_worker && g_capture_tls_accessor_ready) {
    return g_capture_tls_accessor_value;  // 用 capture thread 的 TLS
}
return g_original_tls_accessor(slot);     // 其他线程正常走
```

这是 **一个 if 分支** 的改动。

---

## 四、路线 A 实施计划

### 阶段 1：启用 TLS 覆盖（最小改动）

**目标**：让 piggyback 并行 worker 不再 crash

**改动点**：
1. `hook/src/sns_comment.cpp` — `hooked_tls_accessor()` 函数
   - 加入 worker 线程判断：`t_piggyback_parallel_worker` 为 true 时返回缓存值
   - 添加计数器 `g_tls_accessor_override_hits` 用于诊断
2. 构建 DLL：`cd hook/build && cmake --build . --config Release`
3. 注入测试（按 CLAUDE.md 标准流程：kill → 启动 → 注入 → 验证）

**验证**：
- `piggyback_comment` concurrency=2，1 轮，观察是否 crash
- 如果无 crash，说明 TLS 覆盖生效

### 阶段 2：分级并发压测

**目标**：找到稳定的最大并发数

**步骤**：
1. concurrency=2，10 轮 → 记录成功率 + 耗时
2. concurrency=4，10 轮
3. concurrency=8，10 轮
4. concurrency=10，10 轮
5. 每级要求：成功率 100%（10/10），无新增 SEH 类型

**关注指标**：
- 每级 P50/P95 耗时
- 失败分类（SEH code、timeout、null return）
- 是否出现 `arg1` 竞争迹象（随并发数上升失败率是否阶跃）

**如果 concurrency=N 开始抖动**：
- 回退到 N-2 作为安全并发数
- 分析失败日志确认是 TLS 问题还是 arg1 竞争

### 阶段 3：验收口径收紧

**改动点**：
1. `pyweixin/comment_dispatcher.py` — `post_batch_comments()`
   - 并发可用判定从 `succeeded > 0` 改为 `succeeded == total`
2. `hook/src/pipe_server.cpp` — batch/piggyback 返回
   - `ok` 判定改为全成功才 ok
3. 报表固定字段：`total/succeeded/failed/total_latency_ms/per_comment_latency/seh_code`

### 阶段 4：端到端 50 轮验收

**命令**：
```powershell
python examples/run_hook_e2e_acceptance.py 小蔡 --backend real --rounds 50 --count 10 --concurrency <阶段2确定的值>
```

**达标条件**（5 项全满足）：
1. 连续 ≥ 50 轮
2. 每轮 10/10 成功
3. P95 < 1000ms
4. 不依赖 UI fallback
5. 无新增崩溃类型

### 阶段 5：主流程集成（达标后）

- `moments_ext` 默认走批量发送路径
- 保留 UI fallback 作为降级
- 更新 `moments_rush_guide.md`

---

## 五、风险与止损

| 风险 | 概率 | 止损方案 |
|------|------|----------|
| TLS 覆盖导致新 crash 类型 | 中 | 添加 `--disable-tls-override` 开关，一键回退 |
| 共享 arg1 竞争导致高并发不稳定 | 中 | 回退到安全并发数（如 4 或 6） |
| capture thread TLS 值过期/失效 | 低 | 每次 hook 回调都会刷新缓存值 |
| 微信更新导致 RVA 失效 | 确定 | 特征码扫描 fallback 已实现 |

**B 计划**：如果路线 A 在阶段 2 证明并行无法稳定到 <1s，再考虑：
- Citizen Lab 式 MMTLS 密钥提取（理解协议后在 DLL 内构造请求）
- WeChatSDK.com 付费试用评估

---

## 六、纯 HTTP 路线处置

不删除已有代码和文档，降为 P3 储备：
- `docs/native_http_protocol_recon.md` → 移入 `docs/archive/` 或标注为储备
- `docs/native_http_sender_design.md` → 同上
- `examples/frida_*.js`、`examples/*_probe*.py` → 保留在 examples/，不再主动维护
- 如果路线 A 达标，这些资产作为长期协议理解储备
