import html
import os
from typing import Optional
from models.result import ScanResult
from reporting.masker import SecretMasker


class HTMLReporter:
    SEVERITY_BG = {
        "CRITICAL": "#d9534f",
        "HIGH": "#f0ad4e",
        "MEDIUM": "#ffd152",
        "LOW": "#5bc0de",
        "INFO": "#5cb85c",
    }

    @classmethod
    def generate(cls, result: ScanResult, output_path: Optional[str] = None) -> str:
        # Bắt buộc mask secret trước khi tạo báo cáo HTML
        masked_result = SecretMasker.mask_result(result)
        summary = masked_result.summary

        if output_path is None:
            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, "scan_report.html")
        else:
            dir_name = os.path.dirname(output_path)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)

        esc = html.escape

        # Tạo nội dung HTML với cấu trúc rõ ràng, dễ đọc
        html_lines = [
            "<!DOCTYPE html>",
            "<html lang='vi'>",
            "<head>",
            "  <meta charset='UTF-8'>",
            "  <title>Security Automation Toolkit - Scan Report</title>",
            "  <style>",
            "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 30px; line-height: 1.5; color: #333; }",
            "    h1, h2, h3 { color: #2c3e50; }",
            "    .meta-box { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 6px; margin-bottom: 25px; }",
            "    .summary-grid { display: flex; gap: 15px; margin-bottom: 25px; }",
            "    .summary-card { flex: 1; padding: 12px; border-radius: 6px; text-align: center; color: white; font-weight: bold; }",
            "    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; font-size: 14px; }",
            "    th, td { border: 1px solid #dee2e6; padding: 10px; text-align: left; vertical-align: top; }",
            "    th { background: #e9ecef; }",
            "    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; color: white; }",
            "    code { background: #f1f3f5; padding: 2px 5px; border-radius: 3px; font-family: Consolas, monospace; word-break: break-all; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>🛡️ Báo Cáo Kiểm Tra An Ninh Web</h1>",
            "  <div class='meta-box'>",
            f"    <p><strong>Mục tiêu:</strong> {esc(masked_result.target)}</p>",
            f"    <p><strong>Chế độ:</strong> {esc(masked_result.mode.upper())} | <strong>Thời gian bắt đầu:</strong> {esc(masked_result.start_time)} | <strong>Thời lượng:</strong> {masked_result.duration}s</p>",
            f"    <p><strong>Tổng số requests:</strong> {masked_result.total_requests} | <strong>Endpoints phát hiện:</strong> {summary['total_endpoints']} | <strong>Forms:</strong> {summary['total_forms']}</p>",
            "  </div>",
            "  <h2>Tổng Quan Phát Hiện</h2>",
            "  <div class='summary-grid'>",
        ]

        sc = summary["severity_counts"]
        for sev, bg in [("CRITICAL", "#d9534f"), ("HIGH", "#f0ad4e"), ("MEDIUM", "#ec971f"), ("LOW", "#5bc0de"), ("INFO", "#5cb85c")]:
            count = sc.get(sev, 0)
            html_lines.append(f"    <div class='summary-card' style='background: {bg};'>{sev}<br><span style='font-size: 24px;'>{count}</span></div>")

        html_lines.extend([
            "  </div>",
            "  <h2>Danh Sách Lỗ Hổng & Vấn Đề An Ninh</h2>",
            "  <table>",
            "    <thead>",
            "      <tr>",
            "        <th style='width: 100px;'>Mức Độ</th>",
            "        <th style='width: 110px;'>Trạng Thái</th>",
            "        <th style='width: 180px;'>Loại Phát Hiện</th>",
            "        <th>Endpoint & Chi Tiết</th>",
            "        <th>Bằng Chứng & Khuyến Nghị</th>",
            "      </tr>",
            "    </thead>",
            "    <tbody>",
        ])

        if not masked_result.findings:
            html_lines.append("      <tr><td colspan='5' style='text-align: center; color: green;'>Không phát hiện vấn đề nào trong phạm vi quét.</td></tr>")
        else:
            for f in masked_result.findings:
                bg_color = cls.SEVERITY_BG.get(f.severity.upper(), "#6c757d")
                html_lines.extend([
                    "      <tr>",
                    f"        <td><span class='badge' style='background: {bg_color};'>{esc(f.severity)}</span></td>",
                    f"        <td><strong>{esc(f.status)}</strong><br><small>Độ tin cậy: {esc(f.confidence)}</small></td>",
                    f"        <td><strong>{esc(f.type)}</strong></td>",
                    f"        <td><code>{esc(f.endpoint)}</code><br><br>{esc(f.detail)}</td>",
                    f"        <td>",
                    f"          <strong>Bằng chứng:</strong> <code>{esc(f.evidence) if f.evidence else 'Không'}</code><br>",
                    f"          <strong>Payload:</strong> <code>{esc(f.payload_used) if f.payload_used else 'Không'}</code><br><br>",
                    f"          <strong>Khuyến nghị:</strong> {esc(f.recommendation) if f.recommendation else 'N/A'}",
                    f"        </td>",
                    "      </tr>",
                ])

        html_lines.extend([
            "    </tbody>",
            "  </table>",
            "  <h2>Bản Đồ Bề Mặt Tấn Công (Attack Surface Map)</h2>",
            "  <table>",
            "    <thead>",
            "      <tr>",
            "        <th>URL</th>",
            "        <th>Method</th>",
            "        <th>Status</th>",
            "        <th>Tham Số</th>",
            "        <th>Forms</th>",
            "        <th>Yêu Cầu Auth</th>",
            "      </tr>",
            "    </thead>",
            "    <tbody>",
        ])

        for u, ep in masked_result.attack_surface.items():
            params_str = ", ".join(ep.parameters) if ep.parameters else "None"
            forms_count = len(ep.forms)
            auth_badge = "<span style='color: red; font-weight: bold;'>Có</span>" if ep.auth_required else "Không"
            html_lines.extend([
                "      <tr>",
                f"        <td><code>{esc(ep.url)}</code></td>",
                f"        <td>{esc(ep.method)}</td>",
                f"        <td>{ep.status_code}</td>",
                f"        <td><code>{esc(params_str)}</code></td>",
                f"        <td>{forms_count} form</td>",
                f"        <td>{auth_badge}</td>",
                "      </tr>",
            ])

        html_lines.extend([
            "    </tbody>",
            "  </table>",
            "</body>",
            "</html>",
        ])

        full_html = "\n".join(html_lines)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_html)

        return full_html
