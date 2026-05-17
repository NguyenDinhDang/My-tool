# Security Automation Toolkit

Bo cong cu Python cho cac tac vu kiem tra bao mat co uy quyen, chuyen doi tai lieu va tu dong hoa noi bo.

## Tinh Nang

- Phan tich ma nguon tinh de tim dau hieu loi bao mat.
- Quet bao mat web co ban/nang cao cho website duoc phep kiem thu.
- Phan tich WiFi trong moi truong lab.
- Chuyen file Markdown sang Word `.docx`, co ho tro bang, code block va Mermaid.
- Tu dong dien Google Form khi ban co quyen thuc hien.

## Cai Dat

Yeu cau Python 3.10 tro len.

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Cach Dung Nhanh

```bash
python toolkit.py --help
python toolkit.py info
```

Chuyen Markdown sang Word:

```bash
python toolkit.py md2word samples/mermaid_sample.md
python toolkit.py md2word samples/mermaid_sample.md -o output/result.docx
```

Chuyen nhanh file Markdown trong `samples/`:

```bash
python scripts/convert_samples.py
```

Phan tich ma nguon:

```bash
python src/security/source_code_analyzer.py .
```

Quet web duoc uy quyen:

```bash
python src/security/web_security_scanner.py https://example.com
```

Tu dong dien Google Form:

```bash
python toolkit.py autofill -n 10
```

Chi dung cac cong cu tu dong hoa va bao mat voi he thong, website, form hoac mang ma ban so huu hoac co quyen kiem thu ro rang.

## Cau Truc Du An

```text
.
|-- toolkit.py
|-- toolkit.bat
|-- requirements.txt
|-- config/
|-- docs/
|-- samples/
|-- scripts/
`-- src/
    |-- toolkit_cli.py
    |-- md2word.py
    |-- autoFill_form.py
    |-- quickstart.py
    `-- security/
        |-- source_code_analyzer.py
        |-- web_security_scanner.py
        `-- advanced_wifi_analyzer.py
```

## Tai Lieu Them

- `docs/MERMAID_GUIDE.md`: huong dan Mermaid trong Markdown.
- `docs/SECURITY_TOOLS_GUIDE.txt`: huong dan chi tiet cho analyzer bao mat.
- `docs/PROJECT_STRUCTURE.md`: cau truc du an.
