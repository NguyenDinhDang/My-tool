from typing import Optional
from colorama import Fore, Style, init
from models.result import ScanResult
from reporting.masker import SecretMasker

init(autoreset=True)


class ConsoleReporter:
    SEVERITY_COLORS = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.BLUE,
        "INFO": Fore.GREEN,
    }

    STATUS_ICONS = {
        "VULNERABLE": "[!]",
        "WARNING": "[?]",
        "PASS": "[✓]",
        "INFO": "[i]",
        "ERROR": "[x]",
        "NOT_TESTED": "[-]",
    }

    @classmethod
    def render(cls, result: ScanResult) -> str:
        # Bắt buộc mask secret trước khi hiển thị
        masked_result = SecretMasker.mask_result(result)
        summary = masked_result.summary

        lines = []
        lines.append(f"\n{Fore.CYAN}{'=' * 70}")
        lines.append(f"{Fore.CYAN}       SECURITY AUTOMATION TOOLKIT - BÁO CÁO QUÉT AN NINH")
        lines.append(f"{Fore.CYAN}{'=' * 70}")
        lines.append(f"Target:      {Style.BRIGHT}{masked_result.target}{Style.RESET_ALL}")
        lines.append(f"Chế độ:      {Fore.YELLOW if masked_result.mode == 'active' else Fore.GREEN}{masked_result.mode.upper()}")
        lines.append(f"Thời gian:   {masked_result.start_time} (Thời lượng: {masked_result.duration}s)")
        lines.append(f"Request:     {masked_result.total_requests} requests đã thực hiện")
        lines.append(f"Attack Map:  {summary['total_endpoints']} endpoints | {summary['total_forms']} forms")
        lines.append(f"{Fore.CYAN}{'-' * 70}")

        # Nhóm findings theo severity
        by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in masked_result.findings:
            by_sev.setdefault(f.severity.upper(), []).append(f)

        has_findings = False
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_sev.get(sev, [])
            if not items:
                continue
            has_findings = True
            color = cls.SEVERITY_COLORS.get(sev, Fore.WHITE)
            lines.append(f"\n{color}[ {sev} ] ({len(items)} phát hiện)")

            for idx, item in enumerate(items, 1):
                icon = cls.STATUS_ICONS.get(item.status.upper(), "[*]")
                lines.append(f"  {color}{icon} {item.type} [{item.status}] (Độ tin cậy: {item.confidence})")
                if item.endpoint:
                    lines.append(f"     Endpoint:       {item.endpoint}")
                lines.append(f"     Chi tiết:       {item.detail}")
                if item.evidence:
                    lines.append(f"     Bằng chứng:     {item.evidence}")
                if item.payload_used:
                    lines.append(f"     Payload:        {item.payload_used}")
                if item.recommendation:
                    lines.append(f"     Khuyến nghị:    {item.recommendation}")

        if not has_findings:
            lines.append(f"\n{Fore.GREEN}[✓] Không phát hiện vấn đề an ninh nào trong phạm vi quét.")

        # Bảng tổng kết cuối
        lines.append(f"\n{Fore.CYAN}{'=' * 70}")
        lines.append(f"{Fore.CYAN}TỔNG KẾT KẾT QUẢ QUÉT")
        lines.append(f"{Fore.CYAN}{'=' * 70}")
        sc = summary["severity_counts"]
        lines.append(f"  {Fore.RED}Critical:      {sc.get('CRITICAL', 0)}")
        lines.append(f"  {Fore.RED}High:          {sc.get('HIGH', 0)}")
        lines.append(f"  {Fore.YELLOW}Medium:        {sc.get('MEDIUM', 0)}")
        lines.append(f"  {Fore.BLUE}Low:           {sc.get('LOW', 0)}")
        lines.append(f"  {Fore.GREEN}Info:          {sc.get('INFO', 0)}")

        stc = summary["status_counts"]
        lines.append(f"  Trạng thái:    VULNERABLE={stc.get('VULNERABLE', 0)} | WARNING={stc.get('WARNING', 0)} | PASS={stc.get('PASS', 0)} | NOT_TESTED={stc.get('NOT_TESTED', 0)}")
        lines.append(f"{Fore.CYAN}{'=' * 70}\n")

        output_text = "\n".join(lines)
        print(output_text)
        return output_text
