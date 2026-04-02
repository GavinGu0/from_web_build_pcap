# nDPI 协议 PCAP 生成器

一个强大的网络流量捕获和分析工具，通过自动化浏览器访问网站，使用 nDPI 进行协议识别，并按协议类型拆分 PCAP 文件(nDPI 深度包检测功能被注释了，需要自行开启)。

## 📋 功能特性

- **自动化流量捕获**：使用 Selenium 自动访问网站列表，模拟真实用户行为
- **智能协议识别**：集成 nDPI 深度包检测库进行协议分类
- **PCAP 文件拆分**：按协议类型自动拆分流量文件
- **TLS 密钥记录**：支持 TLS 解密所需的密钥日志
- **彩色日志输出**：实时查看进度和状态信息
- **灵活的配置**：支持多种浏览器、网络接口和抓包过滤器

## 🛠️ 系统要求

### 操作系统
- Windows 10/11（已测试）
- Linux（需要 root 权限）
- macOS

### 必需软件

1. **Python 3.12+**
   - [下载地址](https://www.python.org/downloads/)

2. **Wireshark + TShark**
   - [下载地址](https://www.wireshark.org/download.html)
   - 安装时确保勾选 "Install TShark"
   - 需要将 Wireshark 添加到系统 PATH

3. **nDPI** (可选，用于协议分析)
   - [GitHub 仓库](https://github.com/ntop/nDPI)
   - 需要编译 `ndpiReader` 可执行文件
   - Windows 用户可下载预编译版本

4. **Web 浏览器**
   - Google Chrome（推荐）或 Firefox
   - 对应版本的 WebDriver（ChromeDriver/GeckoDriver）

## 📦 安装步骤

### 1. 克隆项目

```bash
git clone <your-repo-url>
cd ndpi_get_pcap
```

### 2. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

**依赖清单：**
- `selenium>=4.15.0` - 浏览器自动化
- `scapy>=2.5.0` - 数据包处理
- `pyshark>=0.6` - 网络接口检测
- `colorama>=0.4.6` - 彩色终端输出
- `tqdm>=4.66.0` - 进度条显示

### 3. 安装 ChromeDriver（如使用 Chrome）

#### 方法一：自动管理（推荐）
Selenium 4+ 会自动管理 WebDriver，无需手动安装。

#### 方法二：手动安装
1. 查看 Chrome 版本：`chrome://settings/help`
2. 下载对应版本：[ChromeDriver 下载](https://chromedriver.chromium.org/downloads)
3. 将 `chromedriver.exe` 放到项目目录或系统 PATH

### 4. 配置网络接口

运行检测工具查看可用网络接口：

```bash
python check_network_interface.py
```

或：

```bash
python check_interfaces.py
```

**Windows WiFi 接口示例：**
- `WLAN`
- `Wi-Fi`
- `\Device\NPF_{26692EFF-0D71-4060-A5F5-99C04ADBCF82}`

## ⚙️ 配置说明

编辑 [`config.py`](config.py) 文件：

### 网络接口配置

```python
# Windows WiFi 网络接口名称
NETWORK_INTERFACE = r"\Device\NPF_{26692EFF-0D71-4060-A5F5-99C04ADBCF82}"
```

**获取方法：** 运行 `python check_network_interface.py` 查看

### 浏览器配置

```python
BROWSER_TYPE = "chrome"  # 或 "firefox"
HEADLESS_MODE = False    # False=显示浏览器窗口，True=后台运行
CHROME_DRIVER_PATH = None  # None=自动管理，或指定路径
```

### 抓包配置

```python
# 抓包过滤器（tcpdump 语法）
CAPTURE_FILTER = "tcp port 443 or tcp port 80 or udp port 443 or udp port 53"

# 每个 URL 等待时间（秒）
WAIT_TIME_PER_URL = 5

# 页面加载超时（秒）
PAGE_LOAD_TIMEOUT = 30
```

### nDPI 配置

```python
# ndpiReader 可执行文件路径
NDPI_READER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ndpiReader.exe")
```

## 🚀 使用方法

### 准备 URL 列表

编辑 [`urls.txt`](urls.txt) 文件，每行一个 URL：

```txt
https://www.baidu.com
https://www.taobao.com
https://www.youtube.com
```

### 运行主程序

#### 完整流程（抓包 + 分析 + 拆分）

```bash
# Windows
python generate_ndpi_pcap.py

# Linux/Mac（需要 root 权限）
sudo python3 generate_ndpi_pcap.py
```

#### 分步执行

**仅抓包：**
```bash
python generate_ndpi_pcap.py --step capture
```

**仅分析：**
```bash
python generate_ndpi_pcap.py --step analyze
```

**仅拆分：**
```bash
python generate_ndpi_pcap.py --step split
```

### 命令行参数

```bash
python generate_ndpi_pcap.py --help

参数说明:
  --step {all,capture,analyze,split}  执行步骤（默认：all）
  --urls FILE                         URL 列表文件（默认：urls.txt）
  --wait-time SECONDS                 每个 URL 的等待时间（默认：5 秒）
```

## 📁 输出文件

程序运行后会在 `output/` 目录生成以下文件：

```
output/
├── traffic_total.pcap          # 总流量 PCAP 文件
├── tls_keylog.txt              # TLS 解密密钥
├── traffic_analysis.txt        # nDPI 分析结果
├── traffic_analysis.json       # JSON 格式分析结果
├── protocol_stats.txt          # 协议统计信息
├── run.log                     # 运行日志
└── pcap_by_protocol/           # 按协议拆分的 PCAP 文件
    ├── TLS.pcap
    ├── HTTP.pcap
    ├── DNS.pcap
    └── ...
```

## 🔍 工作流程

### 1. 抓包阶段
- 启动 tshark 后台抓包
- 打开浏览器访问 URL 列表
- 对每个 URL 执行通用点击操作（按钮、链接等）
- 保存流量到 PCAP 文件
- 记录 TLS 密钥到日志文件

### 2. nDPI 分析阶段（需配置 nDPI）
- 读取 PCAP 文件
- 使用 ndpiReader 进行深度包检测
- 识别每个数据流的协议类型
- 输出分析结果

### 3. PCAP 拆分阶段
- 解析 nDPI 输出
- 按协议类型分组数据包
- 生成独立的协议 PCAP 文件

## 💡 使用技巧

### 1. 首次运行建议
- 设置 `HEADLESS_MODE = False`，观察浏览器工作状态
- 使用较小的 URL 列表测试（3-5 个网站）
- 检查 `output/run.log` 查看详细日志

### 2. 提高抓包质量
- 关闭其他占用带宽的应用
- 选择稳定的网络连接
- 适当增加 `WAIT_TIME_PER_URL`

### 3. 调试模式
```python
DEBUG_MODE = True      # 启用调试模式
VERBOSE = True         # 详细输出
LOG_LEVEL = "DEBUG"    # 日志级别
```

### 4. 常见问题

**问题 1：找不到 tshark**
```
❌ 找不到 tshark，请确保已安装 Wireshark 并添加到 PATH
```
**解决：** 
- 重新安装 Wireshark，确保勾选 "Install TShark"
- 手动添加 Wireshark 到 PATH：`C:\Program Files\Wireshark`

**问题 2：无法启动浏览器**
```
❌ 启动浏览器失败：Message: unknown error
```
**解决：**
- 更新 ChromeDriver 到最新版本
- 设置 `CHROME_DRIVER_PATH = None` 让 Selenium 自动管理

**问题 3：抓不到数据包**
```
⚠️  文件过小，可能未捕获数据包
```
**解决：**
- 检查 `NETWORK_INTERFACE` 是否正确
- 确认该接口有网络流量
- 尝试调整 `CAPTURE_FILTER` 过滤器

**问题 4：权限不足**
```
❌ 抓包需要 root 权限，请使用 sudo 运行
```
**解决：**
- Windows：以管理员身份运行 PowerShell/CMD
- Linux/Mac：使用 `sudo python3 ...`

## 📝 项目结构

```
ndpi_get_pcap/
├── generate_ndpi_pcap.py    # 主程序
├── config.py                # 配置文件
├── check_interfaces.py      # 接口检测工具（pyshark）
├── check_network_interface.py # 接口检测工具（tshark）
├── urls.txt                 # URL 列表
├── requirements.txt         # Python 依赖
├── pyproject.toml          # 项目配置
├── ndpiReader             # nDPI 可执行文件（需自备）
└── output/                 # 输出目录
```

## 🔧 高级配置

### 自定义抓包过滤器

```python
# 仅捕获 HTTPS 流量
CAPTURE_FILTER = "tcp port 443"

# 捕获所有 TCP 流量
CAPTURE_FILTER = "tcp"

# 排除特定 IP
CAPTURE_FILTER = "tcp and not host 192.168.1.1"
```

### 使用 Firefox 浏览器

```python
BROWSER_TYPE = "firefox"
# CHROME_DRIVER_PATH 改为 GECKO_DRIVER_PATH
```

### 无头模式（后台运行）

```python
HEADLESS_MODE = True
```

## 📊 协议识别示例

nDPI 可以识别 200+ 种协议，包括：

- **Web 协议**: HTTP, HTTPS, TLS
- **流媒体**: YouTube, Netflix, Spotify
- **社交网络**: Facebook, Twitter, Instagram
- **文件传输**: FTP, SFTP, BitTorrent
- **游戏**: Steam, World of Warcraft
- **云服务**: Dropbox, Google Drive, OneDrive

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License

## 👥 作者

GavinGu0

## 🙏 致谢

- [nDPI](https://github.com/ntop/nDPI) - 深度包检测库
- [Selenium](https://www.selenium.dev/) - 浏览器自动化
- [Scapy](https://scapy.net/) - 数据包处理
- [Wireshark](https://www.wireshark.org/) - 网络协议分析器

## 📞 联系方式

如有问题，请提交 GitHub Issue 或联系维护者。

---

**最后更新**: 2026 年 4 月
