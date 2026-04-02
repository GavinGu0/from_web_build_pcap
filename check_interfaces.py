#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""获取可用的网络接口列表"""

try:
    import pyshark
    interfaces = pyshark.get_interface_list()
    
    print("=" * 60)
    print("可用的网络接口列表:")
    print("=" * 60)
    
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    
    print("\n" + "=" * 60)
    print("建议:")
    print("- WiFi 网络通常名为：WLAN, Wi-Fi, 无线网络连接")
    print("- 请选择已连接且有数据流量的接口")
    print("=" * 60)
    
except Exception as e:
    print(f"❌ 错误：{e}")
    print("请确保已安装 pyshark: pip install pyshark")
