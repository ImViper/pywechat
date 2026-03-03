# Native HTTP Protocol Recon (2026-02-12)

## Scope
- Goal: pure HTTP real upstream comment sending (no runtime hook/ui dependency).
- This note records protocol-level reconnaissance and concrete blockers.

## Progress Snapshot (2026-02-12)
1. Real upstream pure HTTP is still blocked by missing pre-encryption request sample.
2. Send-layer evidence is stable: `/mmtls/<id>` encrypted envelope only.
3. Offset timing has been stratified:
   - near-send transport offsets (`0x435900b`, `0x5622d7b`)
   - delayed post-send offsets (`0x1df300e`, `0x1df38d2`, `0x29de835`, `0x29de840`)
   - current pre-send focus candidate: `0x74e2b8`
4. Current next milestone: extract `request_type + plaintext protobuf` at pre-encryption stage.

## Latest facts (verified)
1. `wxbot` does **not** expose Moments comment API.
   - Verified by cloning `jwping/wxbot` and grepping API docs/code.
   - Public APIs focus on chat/contact/db, not SNS comment send.
2. No compatible local upstream was discovered on current machine.
   - `python examples/discover_native_http_upstream.py`
   - Result: `candidate_count=0`
3. `Weixin.dll` contains SNS CGI symbols including:
   - `/cgi-bin/micromsg-bin/mmsnscomment`
   - `/cgi-bin/micromsg-bin/mmsnstimeline`
   - `/cgi-bin/micromsg-bin/mmsnsobjectdetail`
   - `/cgi-bin/micromsg-bin/mmsnspost`
4. Runtime send-layer probe (Frida + winsock hooks) sees:
   - `POST /mmtls/<id> HTTP/1.1`
   - encrypted MMTLS records (`17 f1 04 ...`)
   - **No plaintext `mmsnscomment` URI in send buffers**
   - Example (real UI comment run):
     - `POST /mmtls/000034fd HTTP/1.1` with `Content-Length: 598` and `686`
     - body sample starts with `17f104...` (MMTLS encrypted record)
5. Weixin process attachability and module state are now measurable.
   - `frida_attach_report.json`: total=18, attach_ok=7, ws2_32_loaded_in_attachable=7.
6. CGI string-page access probe found live access during comment send.
   - `mmsnscomment` page hit observed from caller offset `0x1df300e` (relative to `Weixin.dll` base).
   - Candidate offset probe confirms near-send chain includes:
     - `0x435900b`
     - `0x5622d7b`
     - `0x49ffaf0`
     - `0x49f95f2`
     - `0x1df300e`
   - Current argument snapshots in these points still do not expose plaintext `mmsnscomment`.
7. New static xref + runtime timeline correlation is now available.
   - Static capstone scan (`find_weixin_cgi_xrefs.py`) found 8 code xrefs to:
     - `/cgi-bin/micromsg-bin/mmsnscomment`
     - `/cgi-bin/micromsg-bin/mmsnstimeline`
   - Runtime probe on xref offsets confirms these hits exist, but timing indicates they are **post-send side path** in current captures.
8. Candidate offset timing characteristics are now clearer (5-round capture).
   - `0x435900b`, `0x5622d7b`: triggered ~`1-5ms` after `send`, with `/mmtls/` context.
   - `0x1df300e`: mostly `~0.6s-2.3s` after last `send`; saw `micromsg-bin` and occasional `acc-r`.
   - `0x1df38d2`: mostly `~1.5s-2.2s` after last `send`; repeated `acc-r` hits.
   - `0x29de835`, `0x29de840` (cgi xrefs): repeated around `~0.7s` after `send`, with buffer snippet like
     `hook: ... content=acc-r..` (not direct plaintext business packet evidence).
9. Focused probe on `0x74e2b8` captured `acc-rXX-cYY` in `rdx/arg1` **before first send** (~hundreds of ms),
   but current context still looks UI/widget-like and has not yielded protobuf/req-id fields yet.

## What this means
- Winsock/send layer is too late for editable business payload.
- To build pure HTTP comment sender, we must capture data at **pre-encryption stage**:
  - request serialization (`req2buf`/`pack` equivalent),
  - request type mapping (for sns comment),
  - auth/session fields and signature inputs.

## New tools added
1. `examples/extract_weixin_cgi_catalog.py`
   - Extracts CGI catalog directly from `Weixin.dll`.
   - Output: `local_workspace/http_context/weixin_cgi_catalog.json`
2. `examples/probe_weixin_frida_attach.py`
   - Probes which `Weixin/WeChatAppEx` PIDs are Frida-attachable and module state.
   - Output: `local_workspace/http_context/frida_attach_report.json`
3. `examples/frida_wsasend_probe.js`
   - Hooks `send`/`WSASend` and reports payload samples/hits.
4. `examples/frida_cgi_string_probe.js`
   - Monitors memory-page reads of `mmsnscomment/mmsnstimeline/mmsnspost` strings inside `Weixin.dll`.
5. `examples/frida_candidate_callsite_probe.js`
   - Probes candidate callsite offsets discovered from CGI page access events.
6. `examples/frida_offset_args_probe.js`
   - Hooks near-send offsets and dumps pointer arguments/backtrace when invocation is close to `send/WSASend`.
7. `examples/run_frida_probe_with_action.py`
   - Orchestrates: auto-attach Frida probes + run one action command + save unified JSON timeline.
8. `examples/find_weixin_cgi_xrefs.py`
   - Static capstone-based xref scan for CGI strings in `Weixin.dll`.
9. `examples/frida_cgi_xref_runtime_probe.js`
   - Runtime hit/timing probe for xrefs from static scan.
10. `examples/frida_cgi_xref_buffer_dump.js`
   - Deep buffer dump around xref hits (needle windows + struct pointer scan).
11. `examples/frida_token_offsets_timeline_probe.js`
   - Unified timeline for key candidate offsets with `ms_since_last_send`.
12. `examples/frida_offset_74e2b8_focus_probe.js`
   - Focused deep probe for pre-send candidate `0x74e2b8`.

## Commands used now
```powershell
python examples/probe_weixin_frida_attach.py
python examples/extract_weixin_cgi_catalog.py
python examples/find_weixin_cgi_xrefs.py
python examples/run_frida_probe_with_action.py --script examples/frida_token_offsets_timeline_probe.js --action-cmd "python examples/run_hook_e2e_acceptance.py 小蔡 --backend real --rounds 5 --count 1 --concurrency 1 --no-restart-wechat --keep-wechat --open-retries 1 --open-attempt-timeout-s 8 --no-hook-enabled --no-disable-ui-fallback --skip-warmup --no-fail-fast"
```

## Next executable stage (Protocol capture)
1. Keep using `run_frida_probe_with_action.py` as the default capture harness (single report per run).
2. De-prioritize post-send paths:
   - `0x435900b`, `0x5622d7b`, `0x1df300e`, `0x1df38d2`, `0x29de835`, `0x29de840`.
3. Prioritize pre-send candidate expansion from `0x74e2b8`:
   - walk caller/callee chain around this offset,
   - identify stable function boundaries,
   - extract request object fields (`cmd/req-id`, URI mapping, serialized payload pointer/length).
4. Add request-object dump probes that output:
   - pointer + length pairs,
   - candidate protobuf prefix bytes,
   - any `mmsnscomment` mapping evidence before encryption.
5. Only after pre-encryption sample is obtained, proceed to replay PoC and HTTP sender integration.

## Acceptance for this stage
- At least one captured pre-encryption sample that includes:
  - request type (cmd/req id),
  - URI or URI mapping evidence to `mmsnscomment`,
  - plaintext protobuf bytes before business-layer encryption.
