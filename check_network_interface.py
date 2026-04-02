#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络接口检测工具
用于检测系统中可用的网络接口，帮助配置 config.py
"""

import subprocess
import sys

def check_interfaces():
    """检测并显示所有可用的网络接口"""
    
    print("=" * 70)
    print("🔍 网络接口检测工具")
    print("=" * 70)
    
    try:
        # 使用 tshark 获取接口列表
        print("\n📋 正在获取网络接口列表...\n")
        
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=5,
            encoding='utf-8',
            errors='ignore'
        )
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            interfaces = []
            
            print("=" * 70)
            print(f"检测到 {len(lines)} 个网络接口:\n")
            
            for line in lines:
                if line.strip():
                    print(f"  • {line.strip()}")
                    
                    # 提取接口名称
                    if ':' in line:
                        name_part = line.split(':', 1)[1].strip()
                        interfaces.append(name_part)
            
            print("\n" + "=" * 70)
            print("💡 建议:")
            print("-" * 70)
            print("📡 WiFi 网络接口通常包含:")
            print("   • WLAN (Windows 10/11 最常见)")
            print("   • Wi-Fi")
            print("   • 无线网络连接")
            print("")
            print("🔌 有线网络接口通常包含:")
            print("   • Ethernet")
            print("   • 本地连接")
            print("")
            print("✅ 请选择您当前正在使用的网络接口名称（冒号后面的部分）")
            print("=" * 70)
            
            # 给出配置建议
            print("\n📝 配置建议:")
            print("-" * 70)
            print("打开 config.py 文件，修改以下行:")
            print("")
            
            # 推荐 WiFi 接口
            wlan_ifaces = [i for i in interfaces if 'WLAN' in i or 'Wi-Fi' in i or 'Wi-Fi' in i]
            
            if wlan_ifaces:
                print(f'NETWORK_INTERFACE = "{wlan_ifaces[0]}"  # 推荐使用 WiFi 接口')
            else:
                # 如果没有找到 WiFi，推荐第一个非环回接口
                for iface in interfaces:
                    if 'Loopback' not in iface and 'NPF_Loopback' not in iface:
                        print(f'NETWORK_INTERFACE = "{iface}"  # 推荐使用')
                        break
            
            print("")
            print("如果不对，可以尝试:")
            for iface in interfaces[:5]:
                if iface != wlan_ifaces[0] if wlan_ifaces else True:
                    print(f'# NETWORK_INTERFACE = "{iface}"')
            
            print("\n" + "=" * 70)
            
        else:
            print(f"❌ 无法获取接口列表：{result.stderr}")
            print("\n请确保:")
            print("  1. 已安装 Wireshark 或 TShark")
            print("  2. tshark 已添加到系统 PATH")
            print("  3. 以管理员权限运行此脚本")
            
    except FileNotFoundError:
        print("❌ 找不到 tshark 命令")
        print("\n请确保:")
        print("  1. 已安装 Wireshark: https://www.wireshark.org/download.html")
        print("  2. 安装时勾选 'Install TShark'")
        print("  3. 将 Wireshark 添加到系统 PATH")
        print("\n或者直接使用常见接口名:")
        print('  NETWORK_INTERFACE = "WLAN"  # Windows 10/11')
        print('  NETWORK_INTERFACE = "Wi-Fi"')
        
    except subprocess.TimeoutExpired:
        print("❌ 获取接口列表超时")
        
    except Exception as e:
        print(f"❌ 检测失败：{e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_interfaces()
