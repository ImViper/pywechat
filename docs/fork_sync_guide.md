# Fork 同步指南（main 跟上游，开发走独立分支）

## 1. 目标

1. `main` 始终保持与 `upstream/main` 同步。
2. 你的改动都放在 `viper/*` 分支（例如 `viper/moments-custom-v2`）。
3. 需要上游新代码时，从 `main` 同步到你的开发分支。

---

## 2. 远端约定

- `upstream`: 原仓库（Hello-Mr-Crab/pywechat）
- `origin`: 你的 fork（ImViper/pywechat）

---

## 3. 日常流程

### 3.1 同步本地 main

```bash
git switch main
git fetch upstream
git pull --ff-only upstream main
```

### 3.2 把 main 新改动带到开发分支

```bash
git switch viper/moments-custom-v2
git rebase main
```

不想改写提交历史可改用：

```bash
git switch viper/moments-custom-v2
git merge main
```

### 3.3 推送开发分支

```bash
git push -u origin viper/moments-custom-v2
```

---

## 4. 是否同步 fork 的 origin/main（可选）

如果希望 fork 的 `main` 也严格跟随上游：

```bash
git switch main
git push origin main --force-with-lease
```

---

## 5. 保护建议

1. 不要在 `main` 直接做功能提交。
2. 功能分支统一从 `main` 切出。
3. 本地调试产物统一放 `local_workspace/`（已忽略）。

---

## 6. 出问题时恢复

如果需要回看重置前历史，可使用备份分支：

```bash
git switch backup/main-before-repoint
```

再从该分支切新分支继续处理。
