# 🛡️ Threat Detection Platform

**Intelligent Network Traffic Analysis & Adaptive Threat Detection**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](docker-compose.yml)

> 融合规则引擎与无监督机器学习的轻量级网络威胁检测平台
> A lightweight threat detection platform combining rule-based and ML anomaly detection.

---

## 功能 Features

- **实时流量采集** — 基于 PyShark/TShark 的多协议抓包引擎
- **协议解析** — TCP / UDP / DNS / ICMP / TLS / ARP 全协议解析
- **规则检测** — SYN Flood、DNS 隧道、端口扫描三种已知威胁模式
- **ML 异常检测** — Isolation Forest 无监督模型，检测偏离基线的未知异常
- **可视化仪表盘** — Vue 3 + Element Plus + ECharts，暗色安全主题
- **攻击模拟** — 内置 SYN Flood / DNS Tunnel / Port Scan 模拟器
- **Docker 一键部署** — `docker-compose up --build` 三服务启动

## 架构 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Vue 3 Dashboard                       │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│   │ Stat Cards│  │Pie Chart │  │ Alert List│  │Timeline│ │
│   └─────┬────┘  └─────┬────┘  └─────┬────┘  └───┬────┘ │
│         └──────────────┴──────────────┴───────────┘     │
│                          ▼ HTTP                         │
├─────────────────────────────────────────────────────────┤
│                   Flask REST API                         │
│   POST /api/capture    GET /api/analyze/<pcap>          │
│   GET /api/stats       GET /api/alerts                  │
│                          ▼                              │
├─────────────────────────────────────────────────────────┤
│              Detection Engine                            │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│   │ TrafficSniffer│  │ Rule Detector│  │  ML Detector │ │
│   │  (PyShark)    │  │ (3 rules)    │  │ (IsolationF) │ │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│          │                 │                   │         │
│          ▼                 ▼                   ▼         │
│   ┌─────────────────────────────────────────────────┐   │
│   │        Feature Extractor (14-dim vectors)       │   │
│   └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## 快速开始 Quick Start

### Docker 部署（推荐）

```bash
git clone https://github.com/<your-username>/threat-detection-platform.git
cd threat-detection-platform
docker-compose up --build
```

打开浏览器：http://localhost:8080

### 本地开发

```bash
# 后端
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python app.py  # http://localhost:5000

# 前端
cd frontend
npm install
npm run dev  # http://localhost:5173
```

## 演示 Demo

### 1. 启动攻击模拟

```bash
python attack_simulator.py
# 选择 1: SYN Flood -> 输入目标 IP -> 确认攻击
```

### 2. 运行全链路检测

```bash
python full_pipeline.py 30
# 自动抓包 30 秒 -> 规则检测 -> ML 检测 -> 生成 JSON 报告
```

### 3. 查看仪表盘

浏览器打开 http://localhost:5173，点击「开始抓包」，观察告警自动刷新。

## 🖥️ 截图 Screenshots

| 仪表盘主界面 | 告警列表 | 协议分布 |
|:---:|:---:|:---:|
| ![Dashboard](screenshots/dashboard.png) | ![Alerts](screenshots/alerts.png) | ![Protocol](screenshots/protocol.png) |

> ⚠️ 请将截图放入 `screenshots/` 目录

## 技术栈 Tech Stack

| 层级 | 技术 |
|------|------|
| **采集层** | PyShark 0.6 / TShark 4.6 / Scapy 2.7 |
| **检测层** | 规则引擎 + Scikit-learn Isolation Forest |
| **后端** | Python 3.10+ / Flask / Flask-CORS / Gunicorn |
| **前端** | Vue 3 / Vite / Element Plus / ECharts / Axios |
| **监控** | InfluxDB 2.7 / Grafana 12.0 |
| **部署** | Docker / Docker Compose / Nginx |

## 项目结构 Project Structure

```
threat-detection-platform/
├── app.py                    # Flask REST API
├── sniffer.py                # Traffic capture engine
├── rule_detector.py          # Rule-based detection (3 rules)
├── feature_extractor.py      # 14-dim feature extraction
├── ml_detector.py            # Isolation Forest anomaly detection
├── attack_simulator.py       # Attack simulation (3 types)
├── full_pipeline.py          # Full pipeline integration
├── model.pkl                 # Trained ML model
├── requirements.txt          # Python dependencies
├── Dockerfile.backend        # Backend container
├── Dockerfile.frontend       # Frontend container
├── docker-compose.yml        # Service orchestration
├── captures/                 # pcap files
├── results/                  # JSON analysis results
├── frontend/                 # Vue 3 dashboard
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── nginx.conf
│   └── src/
│       ├── main.js
│       ├── App.vue
│       └── views/
│           └── Dashboard.vue
└── README.md
```

## API 文档 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Service info |
| `POST` | `/api/capture` | Start background capture |
| `GET` | `/api/analyze/<pcap>` | Full analysis (rules + ML) |
| `GET` | `/api/stats` | Latest summary for polling |
| `GET` | `/api/alerts?severity=` | Alert list (filter by severity) |

## 检测规则 Detection Rules

| Rule | Logic | Severity |
|------|-------|----------|
| **SYN Flood** | SYN ratio > 70% AND TCP > 100 pkts in 30s window | high |
| **DNS Tunnel** | Domain length > 40 chars OR queries > 50/window | medium |
| **Port Scan** | Unique ports > 50 in 30s window | medium |

## License

MIT License — see [LICENSE](LICENSE) for details.
