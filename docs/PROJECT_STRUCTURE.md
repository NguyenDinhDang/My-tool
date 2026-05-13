# AGI Project Structure

```text
AGI/
|-- agi.py
|-- agi.bat
|-- convert.py
|-- requirements.txt
|-- config/
|   `-- config.py
|-- docs/
|   |-- README.md
|   |-- MERMAID_GUIDE.md
|   |-- PROJECT_STRUCTURE.md
|   `-- SETUP_COMPLETE.txt
|-- samples/
|   `-- mermaid_sample.md
|-- output/
`-- src/
    |-- __init__.py
    |-- agi_cli.py
    |-- autoFill_form.py
    |-- md2word.py
    |-- quickstart.py
    `-- test_click.py
```

## Thu Muc Chinh

| Thu muc | Muc dich |
| --- | --- |
| `src/` | Source code Python |
| `docs/` | Tai lieu huong dan |
| `samples/` | File Markdown mau |
| `output/` | File `.docx` duoc tao ra |
| `config/` | Cau hinh du an |

## Lenh Thuong Dung

```bash
python agi.py --help
python agi.py info
python agi.py md2word samples/mermaid_sample.md
python convert.py
```

## File Quan Trong

- `src/md2word.py`: chuyen Markdown sang Word.
- `src/agi_cli.py`: dinh nghia CLI bang Click.
- `src/autoFill_form.py`: tu dong dien Google Form.
- `README.md`: tai lieu chinh cua du an.
