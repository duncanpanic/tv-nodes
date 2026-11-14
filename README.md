# tv-nodes（流程仓 · public）

本仓库只存自动化流程文件，不含任何节点数据（节点里有服务器地址和密码）。

## 流水线

```
GitHub Actions（国外，每 6 小时）
  subs-check 真内核拨号测活 → output/all.yaml + nodes.json + top10.yaml
  全部产物 → workflow artifact「nodes-run」（保留 2 天）
      ↓
国内网关（tv-nodes-cn.service，每 6 小时 :45）
  用 GitHub Token 下载 artifact → SO_MARK 绕过 TUN 直连逐个拨号
  → 只留国内能连上且能访问外网的 → enrich 打分 → 推私密仓
      ↓
duncanpanic/tv-nodes-private（数据仓 · private）
  nodes.json / top10.yaml / all-cn.yaml
      ↓
网关 nginx 静态发布 → cloudflared tunnel → https://sub.lorcan.top
      ↓
3D 地球小站 + 订阅地址
```

- 订阅地址：`https://sub.lorcan.top/top10.yaml`
- 数据地址：`https://sub.lorcan.top/nodes.json`
