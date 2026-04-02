#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件 - Windows 版本
针对 Windows 笔记本 + WiFi 网络环境配置
"""

import os
import platform

# ============ 网络配置 ============
# Windows WiFi 网络接口名称
# pyshark 需要使用完整的 NPF 设备路径，而不是友好名称
# 从日志中找到的接口：\Device\NPF_{26692EFF-0D71-4060-A5F5-99C04ADBCF82} = WLAN 5
NETWORK_INTERFACE = r"\Device\NPF_{26692EFF-0D71-4060-A5F5-99C04ADBCF82}"

# ============ 文件路径配置 ============
# 输入文件（你需要手动创建这个文件）
URLS_FILE = "urls.txt"

# 输出目录（程序自动创建，不需要你创建）
OUTPUT_DIR = "output"

# 临时文件（全部由程序自动创建）
PCAP_TOTAL = os.path.join(OUTPUT_DIR, "traffic_total.pcap")
TLS_KEYLOG_FILE = os.path.join(OUTPUT_DIR, "tls_keylog.txt")
NDPI_OUTPUT = os.path.join(OUTPUT_DIR, "traffic_analysis.txt")
JSON_OUTPUT = os.path.join(OUTPUT_DIR, "traffic_analysis.json")
PROTOCOL_STATS = os.path.join(OUTPUT_DIR, "protocol_stats.txt")

# 拆分后的PCAP目录（程序自动创建）
PCAP_BY_PROTOCOL_DIR = os.path.join(OUTPUT_DIR, "pcap_by_protocol")

# 日志文件（程序自动创建）
LOG_FILE = os.path.join(OUTPUT_DIR, "run.log")

# ============ 浏览器配置 ============
BROWSER_TYPE = "chrome"  # 或 "firefox"
HEADLESS_MODE = False  # 初次运行建议设为 False，能看到浏览器工作

# ChromeDriver 路径（推荐让 selenium 自动管理）
CHROME_DRIVER_PATH = None  # 设为 None 自动管理

# ============ 抓包配置 ============
# Windows 使用 tshark (Wireshark 自带)
CAPTURE_TOOL = "tshark"

# 抓包过滤器
CAPTURE_FILTER = "tcp port 443 or tcp port 80 or udp port 443 or udp port 53"

# 每个URL等待时间（秒）
WAIT_TIME_PER_URL = 5

# 页面加载超时（秒）
PAGE_LOAD_TIMEOUT = 30

# ============ nDPI 配置 ============
# nDPI 路径（需要先编译安装）
# Windows 上使用绝对路径
NDPI_READER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ndpiReader.exe")
# 或使用其他绝对路径:
# NDPI_READER_PATH = r"C:\Tools\nDPI\example\ndpiReader.exe"

NDPI_CONFIG_FILE = None

# ============ 其他配置 ============
KEEP_UNKNOWN_PROTOCOLS = True
UNKNOWN_PROTOCOL_NAME = "Unknown"
GENERATE_JSON_OUTPUT = True
OPEN_OUTPUT_DIR = True  # Windows 上自动打开输出目录
VERBOSE = True
LOG_LEVEL = "INFO"
CHECK_ADMIN_PRIVILEGES = True
USE_NPCAP = True
DEBUG_MODE = False
