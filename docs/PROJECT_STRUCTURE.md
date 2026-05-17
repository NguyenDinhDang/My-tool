# Project Structure

```text
security-automation-toolkit/
|-- toolkit.py
|-- toolkit.bat
|-- requirements.txt
|-- config/
|   `-- config.py
|-- docs/
|   |-- MERMAID_GUIDE.md
|   |-- PROJECT_STRUCTURE.md
|   `-- SECURITY_TOOLS_GUIDE.txt
|-- samples/
|   |-- mermaid_sample.md
|   `-- vulnerable_sample.py
|-- scripts/
|   `-- convert_samples.py
`-- src/
    |-- __init__.py
    |-- toolkit_cli.py
    |-- autoFill_form.py
    |-- md2word.py
    |-- quickstart.py
    `-- security/
        |-- __init__.py
        |-- advanced_wifi_analyzer.py
        |-- source_code_analyzer.py
        `-- web_security_scanner.py
```

## Thu Muc Chinh

| Thu muc | Muc dich |
| --- | --- |
| `src/` | Source code Python |
| `src/security/` | Cong cu phan tich/kiem thu bao mat co uy quyen |
| `scripts/` | Script tien ich chay thu cong |
| `samples/` | Du lieu mau |
| `docs/` | Tai lieu huong dan |
| `config/` | Cau hinh du an |

## Lenh Thuong Dung

```bash
python toolkit.py --help
python toolkit.py info
python toolkit.py md2word samples/mermaid_sample.md
python scripts/convert_samples.py
python src/security/source_code_analyzer.py .
```
