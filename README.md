<div align="center">

# 🛡️ ThreatSight

**智能网络流量分析与自适应威胁检测平台**

*Intelligent Network Traffic Analysis & Adaptive Threat Detection*

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![License MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](docker-compose.yml)
[![Build](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](.github/workflows/test.yml)

</div>

---

> 融合规则引擎与 Isolation Forest 机器学习的轻量级威胁检测平台，**一条命令启动**，实时监控网络流量，自动识别 SYN Flood、DNS 隧道、端口扫描等攻击行为。

---

## ✨ 功能特性

- 🔄 **实时流量采集** — 基于 PyShark/TShark 的多协议抓包引擎，支持后台持续捕获
- 🧠 **混合智能检测** — 规则引擎（3 类已知攻击）+ Isolation Forest（未知异常），双保险
- 📊 **可视化仪表盘** — Vue 3 + Element Plus + ECharts 深色安全主题，实时告警刷新
- 📜 **历史回溯** — SQLite 持久化每次扫描结果，支持分页浏览、按严重等级筛选
- 📄 **PDF 报告导出** — 一键将仪表盘生成正式检测报告
- ⚙️ **可配置阈值** — Web 界面动态调整检测参数，保存即生效，无需重启
- 🎬 **演示模式** — `DEMO_MODE=true` 自动生成攻击流量并预加载检测结果，零操作即可体验
- 📦 **Docker 一键部署** — `docker-compose up` 三服务（后端 + InfluxDB + Grafana）秒级启动
- 📖 **Swagger API 文档** — 内置 Flasgger 交互式文档，访问 `/apidocs`

---

## 🏗️ 架构

```
┌──────────────────────────────────────────────────────────────────┐
│                       Vue 3 Dashboard                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │ 品牌导航栏 │  │ 统计卡片 │  │ 告警表格 │  │ 协议饼图/时序图 ││
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └────────┬─────────┘│
│        └──────────────┴──────────────┴───────────────┘          │
│                            ▼ HTTP (REST)                        │
├──────────────────────────────────────────────────────────────────┤
│                     Flask REST API (app.py)                      │
│  /api/capture  /api/analyze  /api/stats  /api/alerts            │
│  /api/scans    /api/config   /api/health  /apidocs (Swagger)    │
│                            ▼                                     │
├──────────────────────────────────────────────────────────────────┤
│                      Detection Engine                            │
│  ┌───────────────┐  ┌───────────────┐  ┌──────────────────────┐│
│  │ TrafficSniffer│  │ Rule Detector │  │   ML Detector        ││
│  │  (PyShark)    │  │ SYN/DNS/Port  │  │ Isolation Forest     ││
│  └───────┬───────┘  └───────┬───────┘  └──────────┬───────────┘│
│          │                  │                      │            │
│          ▼                  ▼                      ▼            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │        Feature Extractor (14-dim vectors, per-window)      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            ▼                                     │
├──────────────────────────────────────────────────────────────────┤
│  SQLite DB (scans + alerts)  │  InfluxDB → Grafana (可选)       │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### 前置要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | 3.9+ | 后端运行 |
| Node.js | 16+ | 前端构建 |
| Wireshark/TShark | 4.0+ | 流量解析 |
| Docker | 20+ | 容器部署（可选） |

### 方式一：一键启动脚本（推荐）

```bash
git clone https://github.com/huaishi826/threat-detection-platform.git
cd threat-detection-platform

# Windows
.\start.bat

# Linux / macOS
chmod +x start.sh
./start.sh
```

脚本自动：激活虚拟环境 → 检查依赖 → 启动后端 → 启动前端 → 打开浏览器。

### 方式二：Docker Compose

```bash
# 启动基础设施（InfluxDB + Grafana）
docker-compose -f docker-compose.infra.yml up -d

# 本地启动后端
set DEMO_MODE=true  # Windows
python app.py

# 前端
cd frontend && npm run dev
```

### 方式三：本地开发（分步）

```bash
# 1. 后端
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux/Mac
pip install -r requirements.txt
python app.py                  # http://localhost:5000

# 2. 前端
cd frontend
npm install
npm run dev                    # http://localhost:5173

# 3. 访问
# 仪表盘: http://localhost:5173
# API文档: http://localhost:5000/apidocs
```

---

## 🎬 演示模式

设置环境变量后启动，平台自动加载预置攻击检测结果，无需手动抓包：

```bash
set DEMO_MODE=true   # Windows
export DEMO_MODE=true # Linux/Mac
python app.py
```

打开 http://localhost:5173 即可看到 SYN Flood、DNS Tunnel、Port Scan 三类告警。

---

## 📖 API 文档

启动后端后访问 [Swagger UI](http://localhost:5000/apidocs) 查看完整的交互式 API 文档。

| 方法 | 端点 | 说明 |
|------|------|------|
| `GET` | `/api/health` | 健康检查 |
| `POST` | `/api/capture` | 开始抓包 |
| `POST` | `/api/capture/stop` | 停止抓包 |
| `GET` | `/api/analyze/<pcap>` | 全量分析 |
| `GET` | `/api/stats` | 统计摘要 |
| `GET` | `/api/alerts` | 告警列表 |
| `GET` | `/api/scans` | 历史扫描列表 |
| `GET` | `/api/scans/<id>` | 扫描详情 |
| `GET` | `/api/config` | 获取配置 |
| `POST` | `/api/config` | 更新配置 |
| `GET` | `/api/demo/status` | 演示状态 |

---

## 🔬 检测规则

| 规则 | 逻辑 | 严重等级 |
|------|------|----------|
| **SYN Flood** | SYN 占比 > 70% 且 TCP 包 > 100（10s 窗口） | 🔴 High |
| **DNS Tunnel** | 单域名查询 > 50 次/窗口 或 平均域名长度 > 40 字符 | 🟡 Medium |
| **Port Scan** | 单 IP 探测端口数 > 20（30s 窗口） | 🟡 Medium |
| **ML Anomaly** | Isolation Forest 偏离基线检测 | 🟠 Variable |

---

## 🛠️ 技术栈

| 层级 | 技术 |
|------|------|
| **采集层** | PyShark 0.6 / TShark 4.6 / Scapy 2.7 |
| **检测层** | 规则引擎 + Scikit-learn Isolation Forest |
| **后端** | Python 3.10+ / Flask / Flask-CORS / Flask-SQLAlchemy / Flasgger |
| **前端** | Vue 3 / Vite / Element Plus / ECharts / Axios |
| **数据库** | SQLite（开发）/ PostgreSQL（生产） |
| **监控** | InfluxDB 2.7 / Grafana 12.0 |
| **部署** | Docker / Docker Compose / Nginx |
| **测试** | pytest / GitHub Actions |

---

## 📁 项目结构

```
threat-detection-platform/
├── app.py                    # Flask REST API + Swagger
├── sniffer.py                # 流量采集引擎
├── rule_detector.py          # 规则检测（SYN/DNS/Port）
├── feature_extractor.py      # 14 维特征提取
├── ml_detector.py            # Isolation Forest 异常检测
├── attack_simulator.py       # 攻击模拟器
├── full_pipeline.py          # 全链路流水线
├── config.json               # 检测阈值配置
├── requirements.txt          # Python 依赖
├── .env                      # 环境变量
├── start.bat / start.sh      # 一键启动脚本
├── docker-compose.yml        # Docker 编排
├── Dockerfile.backend        # 后端容器
├── Dockerfile.frontend       # 前端容器
├── tests/                    # 单元测试
│   ├── conftest.py
│   ├── test_rule_detector.py
│   ├── test_feature_extractor.py
│   └── test_ml_detector.py
├── docs/                     # 文档
│   └── USER_GUIDE.md
├── samples/                  # 示例 pcap
│   └── demo.pcap
├── captures/                 # 抓包结果
├── results/                  # 分析结果
└── frontend/                 # Vue 3 前端
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.js
        ├── App.vue
        ├── router/index.js
        └── views/
            ├── Dashboard.vue
            ├── History.vue
            ├── ScanDetail.vue
            └── Settings.vue
```

---

## 🖥️ 截图

| 仪表盘 | 历史记录 | 设置页面 |
|:---:|:---:|:---:|
| ![Dashboard](screenshots/dashboard.png) | ![History](screenshots/history.png) | ![Settings](screenshots/settings.png) |

> ⚠️ 请将截图放入 `screenshots/` 目录

---

## 🧪 测试

```bash
# 安装测试依赖
pip install pytest

# 运行全部测试
pytest tests/ -v

# 运行单个测试文件
pytest tests/test_rule_detector.py -v
```

---

## 📄 License

[MIT License](LICENSE) — 自由使用、修改、分发。

---

## 📖 English Version

# ThreatSight — Intelligent Network Traffic Analysis & Adaptive Threat Detection

ThreatSight is a lightweight network threat detection platform that combines rule-based detection (SYN Flood, DNS Tunnel, Port Scan) with Isolation Forest machine learning for anomaly detection. Features include real-time packet capture, configurable detection thresholds via web UI, SQLite-backed history with pagination, PDF report export, and a Vue 3 dark-themed dashboard.

### Quick Start

```bash
git clone https://github.com/huaishi826/threat-detection-platform.git
cd threat-detection-platform
pip install -r requirements.txt
set DEMO_MODE=true && python app.py
```

Open http://localhost:5173 for the dashboard, http://localhost:5000/apidocs for API docs.

### Tech Stack

- **Backend**: Python 3.10+, Flask, SQLAlchemy, Flasgger
- **Frontend**: Vue 3, Element Plus, ECharts
- **Detection**: Scikit-learn Isolation Forest, custom rule engine
- **Capture**: PyShark / TShark
- **Deploy**: Docker, Nginx, Gunicorn

### Detection Rules

| Rule | Logic | Severity |
|------|-------|----------|
| SYN Flood | SYN ratio > 70%, TCP > 100 pkts / 10s | High |
| DNS Tunnel | >50 queries/domain or avg length >40 / 60s | Medium |
| Port Scan | >20 unique ports from one IP / 30s | Medium |

### License

MIT
