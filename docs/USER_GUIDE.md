# ThreatSight 用户手册

## 1. 系统要求

| 项目 | 最低要求 | 推荐配置 |
|------|----------|----------|
| 操作系统 | Windows 10 / Ubuntu 20.04 / macOS 12+ | Windows 11 / Ubuntu 22.04 |
| Python | 3.9+ | 3.11+ |
| Node.js | 16+ | 20+ LTS |
| 内存 | 4 GB | 8 GB+ |
| 磁盘 | 500 MB | 2 GB+ |
| 网络 | 管理员/root 权限（抓包需要） | — |
| 附加 | Wireshark / TShark 4.0+ | — |

## 2. 安装步骤

### 2.1 Docker 安装（推荐）

```bash
git clone https://github.com/huaishi826/threat-detection-platform.git
cd threat-detection-platform
docker-compose up --build
```

启动后访问：
- 仪表盘：http://localhost:8080
- API 文档：http://localhost:5000/apidocs

### 2.2 本地安装

```bash
# 克隆仓库
git clone https://github.com/huaishi826/threat-detection-platform.git
cd threat-detection-platform

# 安装后端依赖
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux/Mac
pip install -r requirements.txt

# 安装前端依赖
cd frontend
npm install
cd ..
```

### 2.3 一键启动脚本

| 平台 | 命令 |
|------|------|
| Windows | 双击 `start.bat` 或在 PowerShell 中执行 `.\start.bat` |
| Linux/Mac | `chmod +x start.sh && ./start.sh` |

脚本自动完成：虚拟环境激活 → 依赖检查 → 启动后端 → 启动前端 → 打开浏览器。

## 3. 首次使用

### 3.1 开启演示模式

演示模式会自动加载预置的攻击检测数据，无需手动抓包即可体验完整功能。

```bash
# 方法一：环境变量
set DEMO_MODE=true   # Windows
export DEMO_MODE=true # Linux/Mac
python app.py

# 方法二：编辑 .env 文件，确保包含：
DEMO_MODE=true
```

启动后打开 http://localhost:5173，即可看到：
- 🔴 SYN Flood 告警（High）
- 🟡 DNS Tunnel 告警（Medium）
- 🟡 Port Scan 告警（Medium）

### 3.2 确认健康状态

仪表盘左上角绿色呼吸灯表示后端正常运行。如为红色：
1. 检查后端是否启动（终端窗口是否报错）
2. 检查端口 5000 是否被占用：`netstat -ano | findstr :5000`
3. 确认防火墙未阻止 5000 端口

## 4. 功能介绍

### 4.1 实时抓包

1. 打开仪表盘，点击「开始抓包」按钮
2. 选择抓包时长（默认 30 秒）
3. 进度条显示抓包进度
4. 抓包完成后自动触发分析

> ⚠️ 抓包需要管理员权限。Windows 以管理员身份运行终端。

### 4.2 流量分析

抓包完成后，平台自动：
1. 规则引擎检测 3 类已知攻击
2. 特征提取（14 维向量）
3. Isolation Forest ML 异常检测
4. 结果展示在仪表盘

### 4.3 告警管理

- **告警表格**：显示类型、严重等级、时间、源 IP、详情
- **筛选**：点击严重等级标签过滤
- **导出 PDF**：点击「导出 PDF」按钮生成检测报告

### 4.4 历史记录

1. 点击导航栏「历史」进入历史页面
2. 查看所有历史扫描记录
3. 点击某条记录查看详情（协议分布、告警列表、时序图）
4. 支持按时间和状态筛选、分页浏览

### 4.5 配置检测阈值

1. 点击导航栏「设置」进入配置页面
2. 修改参数：
   - SYN Flood：时间窗口、阈值、最小包数
   - DNS 隧道：查询阈值、域名长度阈值
   - 端口扫描：时间窗口、端口阈值
   - ML 模型：contamination 参数
3. 点击「保存配置」立即生效

### 4.6 API 文档

访问 http://localhost:5000/apidocs 打开 Swagger 交互式文档，可直接在浏览器中测试所有 API。

## 5. 常见问题与故障排除

### Q1：启动后端报错 `ModuleNotFoundError: No module named 'flask'`
**原因**：虚拟环境未激活或依赖未安装。
**解决**：
```bash
venv\Scripts\activate
pip install -r requirements.txt
```

### Q2：抓包无数据 / 抓包按钮无反应
**原因**：权限不足或 NPF 驱动未加载。
**解决**：
1. 以管理员身份运行终端
2. 确认 Npcap 已安装（安装 Wireshark 时勾选）
3. 检查接口列表：`python -c "import pyshark; print(pyshark.LiveCapture().interfaces)"`

### Q3：前端页面空白 / 500 Internal Server Error
**原因**：后端未启动或端口冲突。
**解决**：
```bash
# 检查端口占用
netstat -ano | findstr :5000
# 如被占用，结束进程
taskkill /PID <pid> /F
# 重启后端
python app.py
```

### Q4：Docker 启动失败 `Cannot connect to the Docker daemon`
**原因**：Docker Desktop 未运行。
**解决**：启动 Docker Desktop，等待引擎就绪后重试。

### Q5：PDF 导出失败或为空白
**原因**：ECharts 图表未完全渲染或 html2canvas 兼容问题。
**解决**：
1. 确保仪表盘有数据（先执行一次抓包或开启演示模式）
2. 等待所有图表加载完成后再点击导出
3. 尝试刷新页面后重新导出

### Q6：Settings 页面修改配置后检测无变化
**原因**：配置修改只对新扫描生效，不影响已完成的分析结果。
**解决**：修改配置后，重新执行一次抓包 → 分析流程。

### Q7：`tshark not found` 或 PyShark 初始化失败
**原因**：TShark 未安装或路径未配置。
**解决**：
1. 安装 Wireshark（含 TShark）：https://www.wireshark.org/download.html
2. 将 TShark 加入系统 PATH
3. 或修改 `sniffer.py` 中的 `tshark_path` 为实际路径

## 6. 联系方式

- **GitHub Issues**：https://github.com/huaishi826/threat-detection-platform/issues
- **项目地址**：https://github.com/huaishi826/threat-detection-platform

如遇到问题，请在 GitHub Issues 中提交，附上：
1. 操作系统版本
2. Python 版本（`python --version`）
3. 错误信息截图
4. 复现步骤
