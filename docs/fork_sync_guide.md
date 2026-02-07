# Fork 同步说明（本地）

## 当前远端关系

1. `origin`：你的 fork  
   `https://github.com/ImViper/pywechat.git`
2. `upstream`：原仓库  
   `https://github.com/Hello-Mr-Crab/pywechat.git`

当前分支：`main`  
跟踪分支：`origin/main`

---

## 日常同步原仓库（推荐流程）

```bash
git checkout main
git fetch upstream
git merge upstream/main
git push origin main
```

---

## 新功能开发建议

```bash
git checkout -b feat/<name>
# 开发 + 提交
git push -u origin feat/<name>
```

合并回主分支后，再按“日常同步原仓库”流程定期更新。

---

## 本地临时文件约定

本地调试脚本、测试产物、截图、历史草稿统一放在 `local_workspace/`，该目录已加入 `.gitignore`，不会被推送到远端。
