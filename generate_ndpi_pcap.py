#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nDPI协议PCAP生成器
==================
批量访问网站列表，抓取网络流量，使用nDPI进行协议识别，并按协议名拆分成独立的PCAP文件

作者: AI Assistant
版本: 1.0.0
"""

import os
import sys
import time
import random
import json
import subprocess
import signal
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# 第三方库
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from scapy.all import rdpcap, wrpcap, IP, TCP, UDP
    from colorama import init as colorama_init, Fore, Style
    from tqdm import tqdm
except ImportError as e:
    print(f"❌ 缺少依赖库: {e}")
    print("请运行: pip install -r requirements.txt")
    sys.exit(1)

# 导入配置
try:
    import config
except ImportError:
    print("❌ 找不到config.py文件，请确保它在同一目录下")
    sys.exit(1)

# 初始化colorama
colorama_init(autoreset=True)


# ============ 日志配置 ============
class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        # 添加颜色
        if record.levelname in self.COLORS:
            record.levelname = self.COLORS[record.levelname] + record.levelname + Style.RESET_ALL
        return super().format(record)


def setup_logger():
    """设置日志记录器"""
    # 创建输出目录
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    # 创建logger
    logger = logging.getLogger('NDPIGenerator')
    logger.setLevel(getattr(logging, config.LOG_LEVEL))

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = ColoredFormatter(
        '%(levelname)s | %(message)s'
    )
    console_handler.setFormatter(console_formatter)

    # 文件处理器
    file_handler = logging.FileHandler(config.LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)

    # 添加处理器
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()


# ============ 网络抓包类 ============
class NetworkCapture:
    """网络流量抓取器 - 使用 tshark 直接抓包到文件"""

    def __init__(self, interface: str, output_file: str, capture_filter: str = ""):
        """
        初始化抓包器
    
        Args:
            interface: 网络接口名称
            output_file: 输出 PCAP 文件路径
            capture_filter: 抓包过滤器（tcpdump 语法）
        """
        self.interface = interface
        self.output_file = output_file
        self.capture_filter = capture_filter
        self.tshark_process = None

    def start(self):
        """开始抓包 - 使用 tshark 直接写入文件"""
        try:
            # 查找 tshark
            tshark_path = self._find_tshark()
            if not tshark_path:
                logger.error("❌ 找不到 tshark，请确保已安装 Wireshark 并添加到 PATH")
                return False
                
            logger.info(f"🔍 启动 tshark 抓包")
            logger.info(f"   接口：{self.interface}")
            logger.info(f"   过滤器：{self.capture_filter or '无'}")
            logger.info(f"   输出：{self.output_file}")
                
            # 确保输出目录存在
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
                
            # 构建 tshark 命令
            cmd = [
                tshark_path,
                "-i", self.interface,
                "-w", self.output_file,
                "-q"  # 静默模式
            ]
            
            # 添加过滤器
            if self.capture_filter:
                cmd.extend(["-f", self.capture_filter])
            
            # 启动 tshark 进程
            self.tshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            # 等待一下确保抓包已启动
            time.sleep(0.5)
            
            # 检查进程是否正常启动
            if self.tshark_process.poll() is not None:
                stderr = self.tshark_process.stderr.read().decode('utf-8', errors='ignore')
                logger.error(f"❌ tshark 启动失败：{stderr}")
                return False
                
            logger.info(f"✅ 抓包进程已启动")
            return True
                
        except FileNotFoundError:
            logger.error("❌ 找不到 tshark，请确保已安装 Wireshark 并添加到 PATH")
            return False
        except Exception as e:
            logger.error(f"❌ 启动抓包失败：{e}")
            import traceback
            traceback.print_exc()
            return False

    def _find_tshark(self):
        """查找 tshark 可执行文件"""
        # 常见安装路径
        common_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # 尝试从 PATH 中查找
        import shutil
        tshark = shutil.which("tshark")
        if tshark:
            return tshark
            
        return None

    def stop(self):
        """停止抓包"""
        if self.tshark_process:
            logger.info("🛑 停止抓包...")
            try:
                # 发送终止信号
                self.tshark_process.terminate()
                
                # 等待进程结束（最多 10 秒）
                try:
                    self.tshark_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # 强制结束
                    self.tshark_process.kill()
                    self.tshark_process.wait()
                
                # 检查文件是否存在且有内容
                if os.path.exists(self.output_file):
                    file_size = os.path.getsize(self.output_file)
                    if file_size > 24:  # PCAP 文件头大小
                        logger.info(f"✅ 已保存数据包到 {self.output_file} ({file_size} 字节)")
                    else:
                        logger.warning(f"⚠️  文件过小，可能未捕获数据包")
                else:
                    logger.warning("⚠️  未捕获任何数据包")
                
                logger.info("✅ 抓包进程已停止")
            except Exception as e:
                logger.warning(f"⚠️  停止抓包时出错：{e}")
                import traceback
                traceback.print_exc()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# ============ 浏览器自动化类 ============
class BrowserAutomation:
    """浏览器自动化访问"""

    def __init__(self, browser_type: str = "chrome", headless: bool = False,
                 driver_path: Optional[str] = None):
        """
        初始化浏览器自动化

        Args:
            browser_type: 浏览器类型 ("chrome" 或 "firefox")
            headless: 是否使用无头模式
            driver_path: WebDriver 路径
        """
        self.browser_type = browser_type.lower()
        self.headless = headless
        self.driver_path = driver_path
        self.driver = None

    def start(self):
        """启动浏览器"""
        logger.info(f"🌐 启动浏览器：{self.browser_type}")

        try:
            if self.browser_type == "chrome":
                self._start_chrome()
            elif self.browser_type == "firefox":
                self._start_firefox()
            else:
                raise ValueError(f"不支持的浏览器类型：{self.browser_type}")

            logger.info("✅ 浏览器已启动")
            return True
        except Exception as e:
            logger.error(f"❌ 启动浏览器失败：{e}")
            return False

    def _start_chrome(self):
        """启动 Chrome 浏览器"""
        options = ChromeOptions()

        # 基础选项
        if self.headless:
            options.add_argument("--headless")

        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--ignore-certificate-errors")

        # 设置 SSLKEYLOGFILE（用于 TLS 解密）
        os.environ["SSLKEYLOGFILE"] = config.TLS_KEYLOG_FILE
        logger.info(f"📝 TLS 密钥将写入：{config.TLS_KEYLOG_FILE}")

        # 启动浏览器
        if self.driver_path:
            service = ChromeService(executable_path=self.driver_path)
            self.driver = webdriver.Chrome(service=service, options=options)
        else:
            self.driver = webdriver.Chrome(options=options)

    def _start_firefox(self):
        """启动 Firefox 浏览器"""
        options = FirefoxOptions()

        if self.headless:
            options.add_argument("--headless")

        # 设置 SSLKEYLOGFILE
        os.environ["SSLKEYLOGFILE"] = config.TLS_KEYLOG_FILE

        # 启动浏览器
        if self.driver_path:
            service = FirefoxService(executable_path=self.driver_path)
            self.driver = webdriver.Firefox(service=service, options=options)
        else:
            self.driver = webdriver.Firefox(options=options)

    def visit_url(self, url: str, wait_time: int = 5):
        """
        访问 URL

        Args:
            url: 目标 URL
            wait_time: 页面加载后等待时间（秒）
        """
        try:
            logger.info(f"📄 访问：{url}")

            # 设置页面加载超时
            self.driver.set_page_load_timeout(config.PAGE_LOAD_TIMEOUT)

            # 访问 URL
            self.driver.get(url)

            # 等待页面加载
            time.sleep(wait_time)

            logger.info(f"✅ 访问成功：{url}")
            
            # 执行通用点击操作
            self._click_interactive_elements()
            
            return True

        except TimeoutException:
            logger.warning(f"⚠️  页面加载超时：{url}")
            return False
        except WebDriverException as e:
            logger.error(f"❌ 访问失败 {url}: {e}")
            return False

    def _click_interactive_elements(self, max_clicks: int = 10):
        """
        通用点击操作：尝试点击页面上的按钮和链接
        
        Args:
            max_clicks: 最大点击数量
        """
        try:
            logger.info(f"🖱️  开始执行通用点击操作...")
            
            # 存储已点击的元素，避免重复点击
            clicked_elements = set()
            clicks_count = 0
            
            # 获取原始窗口句柄
            original_window = self.driver.current_window_handle
            
            # 1. 尝试点击 <button> 元素
            try:
                buttons = self.driver.find_elements("tag name", "button")
                logger.debug(f"找到 {len(buttons)} 个 button 元素")
                
                for btn in buttons[:max_clicks//2]:  # 限制点击数量
                    try:
                        if btn.is_displayed() and btn.is_enabled():
                            btn_id = id(btn)
                            if btn_id not in clicked_elements:
                                btn.click()
                                clicked_elements.add(btn_id)
                                clicks_count += 1
                                logger.debug(f"   ✓ 点击了 button #{clicks_count}")
                                # 随机延迟 0.1~1.5 秒
                                time.sleep(random.uniform(0.1, 1.5))
                    except Exception:
                        continue  # 忽略单个元素的点击错误
            except Exception:
                pass
            
            # 2. 尝试点击 <a> 超链接
            try:
                links = self.driver.find_elements("tag name", "a")
                logger.debug(f"找到 {len(links)} 个 a 元素")
                
                for link in links[:max_clicks]:  # 限制点击数量
                    try:
                        if link.is_displayed():
                            link_text = link.text.strip()
                            # 跳过空链接、javascript 链接、锚点链接
                            href = link.get_attribute('href') or ''
                            if (href.startswith('javascript:') or 
                                href.startswith('#') or 
                                not href or 
                                len(link_text) == 0):
                                continue
                            
                            link_id = id(link)
                            if link_id not in clicked_elements:
                                # 使用 JavaScript 点击，更可靠
                                self.driver.execute_script("arguments[0].click();", link)
                                clicked_elements.add(link_id)
                                clicks_count += 1
                                logger.debug(f"   ✓ 点击了 link #{clicks_count}: {link_text[:30]}")
                                # 随机延迟 0.1~1.5 秒
                                time.sleep(random.uniform(0.1, 1.5))
                                
                                # 如果打开了新窗口/标签页，关闭它并返回原窗口
                                time.sleep(0.3)
                                current_windows = self.driver.window_handles
                                if len(current_windows) > 1:
                                    for window_handle in current_windows:
                                        if window_handle != original_window:
                                            self.driver.switch_to.window(window_handle)
                                            self.driver.close()
                                    self.driver.switch_to.window(original_window)
                    except Exception:
                        continue  # 忽略单个元素的点击错误
            except Exception:
                pass
            
            # 3. 尝试点击带有常见可点击类名的元素
            common_clickable_classes = ['btn', 'button', 'clickable', 'link', 'nav-link', 'menu-item']
            for class_name in common_clickable_classes:
                try:
                    elements = self.driver.find_elements("css selector", f".{class_name}")
                    for elem in elements[:3]:  # 每个类名最多点击 3 个
                        try:
                            if elem.is_displayed():
                                elem_id = id(elem)
                                if elem_id not in clicked_elements:
                                    self.driver.execute_script("arguments[0].click();", elem)
                                    clicked_elements.add(elem_id)
                                    clicks_count += 1
                                    logger.debug(f"   ✓ 点击了 .{class_name} #{clicks_count}")
                                    # 随机延迟 0.1~1.5 秒
                                    time.sleep(random.uniform(0.1, 1.5))
                        except Exception:
                            continue
                except Exception:
                    continue
            
            # 4. 尝试点击 input[type='button'], input[type='submit']
            try:
                input_buttons = self.driver.find_elements("css selector", "input[type='button'], input[type='submit']")
                for inp in input_buttons[:3]:
                    try:
                        if inp.is_displayed() and inp.is_enabled():
                            inp_id = id(inp)
                            if inp_id not in clicked_elements:
                                inp.click()
                                clicked_elements.add(inp_id)
                                clicks_count += 1
                                logger.debug(f"   ✓ 点击了 input button #{clicks_count}")
                                # 随机延迟 0.1~1.5 秒
                                time.sleep(random.uniform(0.1, 1.5))
                    except Exception:
                        continue
            except Exception:
                pass
            
            # 确保回到原始窗口
            try:
                self.driver.switch_to.window(original_window)
            except Exception:
                pass
            
            logger.info(f"✅ 完成点击操作，共点击 {clicks_count} 个元素")
            
            # 等待所有网络请求完成
            time.sleep(2)
            
        except Exception as e:
            logger.debug(f"⚠️  点击操作执行异常：{e}")
            # 不抛出异常，不影响主流程

    def close(self):
        """关闭浏览器"""
        if self.driver:
            logger.info("🔒 关闭浏览器")
            self.driver.quit()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ============ nDPI分析类 ============
class NDPIAnalyzer:
    """nDPI协议分析器"""

    def __init__(self, ndpi_reader_path: str):
        """
        初始化nDPI分析器

        Args:
            ndpi_reader_path: ndpiReader可执行文件路径
        """
        self.ndpi_reader_path = ndpi_reader_path

    def analyze_pcap(self, pcap_file: str, output_file: str) -> bool:
        """
        使用nDPI分析PCAP文件

        Args:
            pcap_file: 输入PCAP文件路径
            output_file: 输出分析结果文件路径

        Returns:
            是否成功
        """
        if not os.path.exists(self.ndpi_reader_path):
            logger.error(f"❌ 找不到ndpiReader: {self.ndpi_reader_path}")
            logger.info("请先编译安装nDPI，并修改config.py中的NDPI_READER_PATH")
            return False

        cmd = [self.ndpi_reader_path, "-i", pcap_file]

        logger.info(f"🔬 运行nDPI分析: {pcap_file}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )

            # 保存输出
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result.stdout)

            logger.info(f"✅ 分析结果已保存: {output_file}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"❌ nDPI分析失败: {e}")
            logger.error(f"错误输出: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"❌ 运行nDPI时出错: {e}")
            return False

    def parse_ndpi_output(self, output_file: str) -> Dict[Tuple[str, int, str, int, str], str]:
        """
        解析nDPI输出，提取流信息

        Args:
            output_file: nDPI输出文件路径

        Returns:
            流到协议的映射字典，key为五元组，value为协议名
        """
        logger.info(f"📊 解析nDPI输出: {output_file}")

        flow_to_protocol = {}

        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # nDPI输出格式示例（需要根据实际输出调整）:
            # 2024/01/01 12:00:00 [TCP] 192.168.1.2:1234 -> 93.184.216.34:443 [TLS]
            # 这是一个简化版本，实际需要根据ndpiReader的真实输出格式调整

            for line in lines:
                # TODO: 根据实际的ndpiReader输出格式进行解析
                # 这里提供一个示例解析逻辑
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # 示例解析（需要根据实际情况调整）
                # 假设格式为: [协议] 源IP:源端口 -> 目的IP:目的端口 [应用协议]
                # 实际使用时需要根据ndpiReader的真实输出格式修改这部分

                pass

            logger.info(f"✅ 解析完成，找到 {len(flow_to_protocol)} 条流")

        except Exception as e:
            logger.error(f"❌ 解析nDPI输出失败: {e}")

        return flow_to_protocol


# ============ PCAP拆分器 ============
class PCAPSplitter:
    """PCAP文件拆分器"""

    def __init__(self, flow_to_protocol: Dict[Tuple[str, int, str, int, str], str]):
        """
        初始化拆分器

        Args:
            flow_to_protocol: 流到协议的映射
        """
        self.flow_to_protocol = flow_to_protocol

    def split_pcap(self, input_pcap: str, output_dir: str):
        """
        按协议拆分PCAP文件

        Args:
            input_pcap: 输入PCAP文件
            output_dir: 输出目录
        """
        logger.info(f"✂️  拆分PCAP文件: {input_pcap}")

        os.makedirs(output_dir, exist_ok=True)

        try:
            # 读取PCAP
            packets = rdpcap(input_pcap)
            logger.info(f"📦 读取到 {len(packets)} 个数据包")

            # 按协议分组
            protocol_packets = {}

            for pkt in tqdm(packets, desc="处理数据包"):
                # 获取五元组
                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]

                # 确定传输层协议
                if pkt.haslayer(TCP):
                    transport_layer = pkt[TCP]
                    proto = "TCP"
                elif pkt.haslayer(UDP):
                    transport_layer = pkt[UDP]
                    proto = "UDP"
                else:
                    continue

                # 构建流键
                flow_key = (
                    ip_layer.src,
                    transport_layer.sport,
                    ip_layer.dst,
                    transport_layer.dport,
                    proto
                )

                # 查找协议名
                protocol = self.flow_to_protocol.get(flow_key, config.UNKNOWN_PROTOCOL_NAME)

                # 添加到对应协议组
                if protocol not in protocol_packets:
                    protocol_packets[protocol] = []
                protocol_packets[protocol].append(pkt)

            # 写入各协议的PCAP文件
            for protocol, pkts in protocol_packets.items():
                if protocol == config.UNKNOWN_PROTOCOL_NAME and not config.KEEP_UNKNOWN_PROTOCOLS:
                    continue

                output_file = os.path.join(output_dir, f"{protocol}.pcap")
                wrpcap(output_file, pkts)
                logger.info(f"✅ {protocol}.pcap: {len(pkts)} 个数据包")

            logger.info(f"✅ 拆分完成，共生成 {len(protocol_packets)} 个协议PCAP文件")

        except Exception as e:
            logger.error(f"❌ 拆分PCAP失败: {e}")


# ============ 主工作流 ============
def main_workflow(urls: List[str], step: str = "all"):
    """
    主工作流

    Args:
        urls: URL 列表
        step: 执行步骤 ("all", "capture", "analyze", "split")
    """
    logger.info("=" * 60)
    logger.info(f"{Fore.CYAN}nDPI 协议 PCAP 生成器 v1.0{Style.RESET_ALL}")
    logger.info("=" * 60)

    # 创建输出目录
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    os.makedirs(config.PCAP_BY_PROTOCOL_DIR, exist_ok=True)

    # 步骤 1: 抓包 + 访问网站（每个 URL 单独抓包）
    if step in ["all", "capture"]:
        logger.info("\n" + "=" * 60)
        logger.info(f"{Fore.YELLOW}步骤 1/2: 抓包与网站访问{Style.RESET_ALL}")
        logger.info("=" * 60)

        # 启动浏览器
        browser = BrowserAutomation(
            browser_type=config.BROWSER_TYPE,
            headless=config.HEADLESS_MODE,
            driver_path=config.CHROME_DRIVER_PATH
        )

        try:
            # 启动浏览器
            if not browser.start():
                logger.error("❌ 无法启动浏览器，程序退出")
                return

            # 访问 URL 列表 - 每个 URL 单独抓包
            logger.info(f"📋 开始访问 {len(urls)} 个 URL（每个 URL 独立抓包）")

            for i, url in enumerate(urls, 1):
                logger.info(f"\n{'='*60}")
                logger.info(f"[{i}/{len(urls)}] 处理：{url}")
                logger.info(f"{'='*60}")
                
                # 生成基于 URL 的文件名
                from urllib.parse import urlparse
                parsed = urlparse(url)
                # 文件名格式：example_com_8080.pcap
                safe_name = f"{parsed.netloc.replace(':', '_')}"
                if not safe_name:
                    safe_name = f"url_{i}"
                pcap_file = os.path.join(config.OUTPUT_DIR, f"{safe_name}.pcap")
                
                logger.info(f"💾 抓包文件：{pcap_file}")
                
                # 启动抓包
                capture = NetworkCapture(
                    interface=config.NETWORK_INTERFACE,
                    output_file=pcap_file,
                    capture_filter=config.CAPTURE_FILTER
                )
                
                try:
                    # 开始抓包
                    if not capture.start():
                        logger.error(f"❌ 无法启动抓包，跳过：{url}")
                        continue
                    
                    # 访问 URL
                    browser.visit_url(url, config.WAIT_TIME_PER_URL)
                    
                finally:
                    # 停止抓包
                    capture.stop()
                    logger.info(f"✅ 已保存：{pcap_file}")
                
                # 如果不是最后一个 URL，延迟 1 秒再处理下一个
                if i < len(urls):
                    logger.info(f"⏳ 等待 1 秒后处理下一个 URL...")
                    time.sleep(1)

            logger.info("\n✅ 所有 URL 访问完成")

        finally:
            # 关闭浏览器
            browser.close()

        logger.info(f"\n✅ 抓包文件已保存到：{config.OUTPUT_DIR}")

    # 步骤 2: nDPI 分析（已屏蔽）
    # if step in ["all", "analyze"]:
    #     logger.info("\n" + "=" * 60)
    #     logger.info(f"{Fore.YELLOW}步骤 2/3: nDPI 协议分析{Style.RESET_ALL}")
    #     logger.info("=" * 60)
    #
    #     analyzer = NDPIAnalyzer(config.NDPI_READER_PATH)
    #
    #     if not analyzer.analyze_pcap(config.PCAP_TOTAL, config.NDPI_OUTPUT):
    #         logger.error("❌ nDPI 分析失败")
    #         return
    #
    #     # 解析结果
    #     flow_to_protocol = analyzer.parse_ndpi_output(config.NDPI_OUTPUT)

    # 步骤 3: 拆分 PCAP（已屏蔽）
    # if step in ["all", "split"]:
    #     logger.info("\n" + "=" * 60)
    #     logger.info(f"{Fore.YELLOW}步骤 3/3: 拆分 PCAP 文件{Style.RESET_ALL}")
    #     logger.info("=" * 60)
    #
    #     # 如果之前没有解析，需要重新解析
    #     if 'flow_to_protocol' not in locals():
    #         analyzer = NDPIAnalyzer(config.NDPI_READER_PATH)
    #         flow_to_protocol = analyzer.parse_ndpi_output(config.NDPI_OUTPUT)
    #
    #     splitter = PCAPSplitter(flow_to_protocol)
    #     splitter.split_pcap(config.PCAP_TOTAL, config.PCAP_BY_PROTOCOL_DIR)

    # 完成
    logger.info("\n" + "=" * 60)
    logger.info(f"{Fore.GREEN}✅ 所有任务完成！{Style.RESET_ALL}")
    logger.info("=" * 60)
    logger.info(f"📁 输出目录：{config.OUTPUT_DIR}")
    logger.info(f"📝 日志文件：{config.LOG_FILE}")


# ============ 主函数 ============
def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="nDPI协议PCAP生成器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 完整流程
  sudo python3 generate_ndpi_pcap.py

  # 仅抓包
  sudo python3 generate_ndpi_pcap.py --step capture

  # 仅分析
  python3 generate_ndpi_pcap.py --step analyze

  # 仅拆分
  python3 generate_ndpi_pcap.py --step split
        """
    )

    parser.add_argument(
        '--step',
        choices=['all', 'capture', 'analyze', 'split'],
        default='all',
        help='执行步骤'
    )

    parser.add_argument(
        '--urls',
        default=config.URLS_FILE,
        help='URL列表文件'
    )

    parser.add_argument(
        '--wait-time',
        type=int,
        default=config.WAIT_TIME_PER_URL,
        help='每个URL的等待时间（秒）'
    )

    args = parser.parse_args()

    # 检查权限
    if args.step in ['all', 'capture']:
        if os.name != 'nt' and os.geteuid() != 0:
            logger.error("❌ 抓包需要root权限，请使用sudo运行")
            sys.exit(1)

    # 读取URL列表
    if not os.path.exists(args.urls):
        logger.error(f"❌ 找不到URL文件: {args.urls}")
        sys.exit(1)

    with open(args.urls, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not urls:
        logger.error("❌ URL列表为空")
        sys.exit(1)

    logger.info(f"📋 读取到 {len(urls)} 个URL")

    # 运行主工作流
    try:
        main_workflow(urls, args.step)
    except KeyboardInterrupt:
        logger.warning("\n⚠️  用户中断程序")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ 程序出错: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
