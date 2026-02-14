# 整体流程图（多评论监听）

```mermaid
flowchart TD
    A[启动监听脚本\nrun_feed_multi_comment_listener.py] --> B[解析参数/时间窗口\n加载 ARK_API_KEY]
    B --> C[初始化 OCR/AI Provider]
    C --> D[组装多源回调\nOCR + AI + 预制 + OCR重试]
    D --> E[设置环境变量\nHOOK_ENABLED=1\nBATCH_MODE=fast_first_batch\nMAX_CONCURRENCY=1]
    E --> F[进入轮询窗口]

    F --> G[打开/复用朋友圈窗口]
    G --> H[fetch_and_comment_from_moments_feed]
    H --> I[抓取目标帖子\n校验 author + fingerprint\n提取图片]
    I --> J[启动多源并发生成\ncreate_multi_source_streaming_callback]
    J --> Q[(答案队列 Queue)]

    H --> K{Hook Dispatcher 可用?}
    K -->|是| L{batch_mode}
    K -->|否| U[UI 流式发送路径\n逐条 comment_flow]

    L -->|fast_first_batch| M[等待首条答案 <=2s]
    M --> N[首条立即发送\npost_comment(author+content_hash)]
    N --> O[继续收集剩余答案 <=8s]
    O --> P[批量发送剩余\npost_batch_comments Serial]
    L -->|piggyback/parallel/serial| R[收集全部答案后批量发送]

    U --> V[预开评论编辑器]
    V --> W[逐条从 Queue 取答案并发送]

    Q --> M
    Q --> O
    Q --> R
    Q --> W

    P --> X[写入状态文件\nrush_state_feed_*_multi.json]
    R --> X
    W --> X
    X --> Y[结束或继续下一轮]
```
