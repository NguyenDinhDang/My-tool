#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
LEGAL DISCLAIMER / TUYÊN BỐ MIỄN TRỪ TRÁCH NHIỆM PHÁP LÝ
==============================================================================
Dự án này được tạo ra ĐỘC QUYỀN vì mục đích giáo dục, nghiên cứu an toàn thông
tin và phục vụ học thuật trong môi trường phòng thí nghiệm khép kín (Local Lab).

1. Yêu cầu cấp phép: Tuyệt đối KHÔNG sử dụng công cụ này để quét, bắt gói tin,
   hoặc can thiệp vào bất kỳ hệ thống nào mà không có sự đồng ý bằng văn bản.
2. Không khuyến khích hành vi phi pháp: Nghiêm cấm mọi hành vi lạm dụng mã nguồn.
3. Miễn trừ trách nhiệm: Tác giả (Đặng Đình Nguyên) KHÔNG chịu bất kỳ trách nhiệm
   pháp lý nào đối với các thiệt hại phát sinh từ việc sử dụng công cụ này.
==============================================================================

DEMO: Tại sao Windows chỉ thấy traffic của chính mình (Educational Simulation).
"""

from scapy.all import *
from colorama import Fore, init
import platform

init(autoreset=True)

def check_capabilities():
    """Kiểm tra khả năng của hệ thống"""
    
    print(f"{Fore.CYAN}{'='*60}")
    print(f"NETWORK CAPTURE CAPABILITIES CHECK")
    print(f"{'='*60}\n")
    
    # Hệ điều hành
    os_name = platform.system()
    print(f"OS: {Fore.YELLOW}{os_name}")
    
    # List interfaces
    print(f"\n{Fore.GREEN}Available Interfaces:")
    for iface in conf.ifaces.values():
        print(f"  - {iface.description}")
    
    # Check monitor mode support
    print(f"\n{Fore.CYAN}Monitor Mode Support:")
    
    if os_name == "Linux":
        print(f"  {Fore.GREEN}✓ Linux hỗ trợ Monitor Mode")
        print(f"  {Fore.GREEN}✓ Có thể bắt traffic của người khác")
        print(f"  {Fore.GREEN}✓ Commands: airmon-ng, iwconfig")
    
    elif os_name == "Windows":
        print(f"  {Fore.RED}✗ Windows KHÔNG hỗ trợ Monitor Mode")
        print(f"  {Fore.RED}✗ CHỈ bắt được traffic của chính máy bạn")
        print(f"  {Fore.RED}✗ Driver bị giới hạn bởi Microsoft")
        
        print(f"\n{Fore.YELLOW}Windows Limitations:")
        print(f"  • Card WiFi hoạt động ở Managed Mode")
        print(f"  • Driver lọc bỏ packets không phải của bạn")
        print(f"  • Không có API để enable promiscuous mode")
        
        print(f"\n{Fore.CYAN}Bạn CÓ THỂ bắt trên Windows:")
        print(f"  {Fore.GREEN}✓ Traffic HTTP/HTTPS của chính bạn")
        print(f"  {Fore.GREEN}✓ DNS queries của chính bạn")
        print(f"  {Fore.GREEN}✓ Connections từ apps trên máy bạn")
        
        print(f"\n{Fore.RED}Bạn KHÔNG THỂ bắt trên Windows:")
        print(f"  {Fore.RED}✗ Traffic của máy khác trên cùng WiFi")
        print(f"  {Fore.RED}✗ Passwords của người khác")
        print(f"  {Fore.RED}✗ Web browsing của người khác")
    
    elif os_name == "Darwin":  # macOS
        print(f"  {Fore.YELLOW}~ macOS có giới hạn monitor mode")
        print(f"  {Fore.YELLOW}~ Cần tool đặc biệt như Airport")
    
    print(f"\n{Fore.CYAN}{'='*60}")

def demo_packet_filtering():
    """Demo cách Windows lọc packets (Mô phỏng dữ liệu an toàn)"""
    
    print(f"\n{Fore.YELLOW}PACKET FILTERING DEMO (SAFE LAB SIMULATION)")
    print(f"{'='*60}\n")
    
    print("Giả sử có 3 máy trên mạng nội bộ Lab (RFC 1918):")
    print(f"  • Máy A (192.168.1.10) - Thiết bị của bạn")
    print(f"  • Máy B (192.168.1.20) - Thiết bị mẫu Alice (Simulated)")
    print(f"  • Máy C (192.168.1.30) - Thiết bị mẫu Bob (Simulated)\n")
    
    print("Mô phỏng lưu lượng trong môi trường Lab:")
    packets = [
        ("A → Router", "192.168.1.10 → 192.168.1.1", "Web request mẫu"),
        ("B → Router", "192.168.1.20 → 192.168.1.1", "Email test traffic"),
        ("Router → A", "192.168.1.1 → 192.168.1.10", "Web response mẫu"),
        ("Router → B", "192.168.1.1 → 192.168.1.20", "Email test response"),
        ("C → Router", "192.168.1.30 → 192.168.1.1", "Mock test authentication"),
    ]
    
    print(f"{Fore.CYAN}Linux với Monitor Mode:")
    for desc, flow, content in packets:
        print(f"  {Fore.GREEN}✓ CAPTURED: {desc} | {flow} | {content}")
    
    print(f"\n{Fore.RED}Windows (Managed Mode):")
    for desc, flow, content in packets:
        if "192.168.1.10" in flow:  # Only your traffic
            print(f"  {Fore.GREEN}✓ CAPTURED: {desc} | {flow} | {content}")
        else:
            print(f"  {Fore.RED}✗ FILTERED: {desc} | {flow} | {Fore.LIGHTBLACK_EX}{content}")
    
    print(f"\n{Fore.YELLOW}Kết luận:")
    print(f"  • Linux: Bắt được {len(packets)}/{len(packets)} packets")
    print(f"  • Windows: Bắt được 2/{len(packets)} packets (chỉ của bạn)")

def show_workarounds():
    """Hướng dẫn thiết lập môi trường Virtual Lab an toàn"""
    
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"HƯỚNG DẪN THỰC HÀNH AN TOÀN TRONG LOCAL LAB")
    print(f"{'='*60}\n")
    
    print(f"{Fore.CYAN}Option 1: Dùng Dedicated Virtual Lab (Khuyên dùng)")
    print("""
  • Tạo virtual network trong VirtualBox/VMware/QEMU.
  • Tạo nhiều máy ảo làm môi trường thực hành khép kín.
  • Đảm bảo 100% cách ly, an toàn, tuân thủ pháp luật và đạo đức nghề nghiệp.
    """)
    
    print(f"{Fore.CYAN}Option 2: Học từ PCAP Captures công khai chuẩn")
    print("""
  • Tải các file PCAP mẫu hợp pháp từ:
    - https://wiki.wireshark.org/SampleCaptures
    - https://www.netresec.com/
  • Phân tích offline với Wireshark / Scapy.
  • Rèn luyện kỹ năng phân tích mà không cần gửi gói tin ra mạng thật.
    """)
    
    print(f"{Fore.RED}LƯU Ý BẮT BUỘC:")
    print(f"  ⚠️  Bắt gói tin người khác mà không có văn bản ủy quyền là vi phạm pháp luật.")
    print(f"  ⚠️  Chỉ thực hành trên mạng và thiết bị do chính bạn sở hữu hoặc quản lý.")

def main():
    check_capabilities()
    demo_packet_filtering()
    show_workarounds()
    
    print(f"\n{Fore.GREEN}{'='*60}")
    print("Tóm tắt:")
    print("="*60)
    print("""
Windows: Chỉ thấy traffic của CHÍNH BẠN
  → Đủ để học phân tích an toàn mạng cơ bản
  → Đủ để phân tích và gỡ lỗi ứng dụng nội bộ
  → Phục vụ phòng thủ an ninh và giám sát máy trạm
    """)

if __name__ == "__main__":
    main()
