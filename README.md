# AGI CLI

AGI CLI la bo cong cu dong lenh gom cac tien ich tu dong hoa va chuyen doi tai lieu. Du an hien co hai tinh nang chinh: chuyen file Markdown sang Word va tu dong dien Google Form khi ban co quyen thuc hien.

## Tinh Nang

- Chuyen Markdown sang Word `.docx`
- Ho tro heading, bang, danh sach, link, blockquote, code block va Mermaid diagram
- Tu dong dien Google Form bang Selenium va undetected-chromedriver
- Co launcher Windows `agi.bat` va file chay truc tiep `agi.py`

## Cai Dat

Yeu cau Python 3.7 tro len.

```bash
pip install -r requirements.txt
```

Neu dung moi truong ao:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Cach Dung

Chay tu thu muc goc cua du an:

```bash
python agi.py --help
```

Hoac dung launcher tren Windows:

```bash
.\agi.bat --help
```

### Chuyen Markdown Sang Word

```bash
python agi.py md2word samples/mermaid_sample.md
```

Chi dinh file dau ra:

```bash
python agi.py md2word samples/mermaid_sample.md -o output/result.docx
```

Neu file Markdown nam trong `samples/`, ban co the truyen truc tiep ten file:

```bash
python agi.py md2word mermaid_sample.md
```

### Dung Script Chuyen Doi Nhanh

```bash
python convert.py
```

Script nay liet ke cac file `.md` trong `samples/` va giup chuyen sang `.docx`.

### Tu Dong Dien Google Form

```bash
python agi.py autofill -n 10
```

Chi dung tinh nang nay voi form ma ban co quyen dien. Cau hinh URL va danh sach cau tra loi trong `src/autoFill_form.py` truoc khi chay.

### Xem Thong Tin Cong Cu

```bash
python agi.py info
```

## Cau Truc Du An

```text
.
|-- agi.py
|-- agi.bat
|-- convert.py
|-- requirements.txt
|-- config/
|-- docs/
|-- output/
|-- samples/
`-- src/
    |-- agi_cli.py
    |-- autoFill_form.py
    |-- md2word.py
    `-- quickstart.py
```

## Ghi Chu Mermaid

Cong cu Markdown to Word se thu render Mermaid diagram theo thu tu:

1. Dung `mmdc` neu may da cai Mermaid CLI.
2. Dung Mermaid Ink online API neu co internet.
3. Neu ca hai cach tren khong kha dung, nhung source Mermaid vao Word kem link `mermaid.live`.

Neu muon cai Mermaid CLI:

```bash
npm install -g @mermaid-js/mermaid-cli
```

## Tai Lieu Them

- `docs/MERMAID_GUIDE.md`: huong dan Mermaid
- `docs/PROJECT_STRUCTURE.md`: cau truc du an
- `samples/`: cac file Markdown mau

## License

Du an duoc cung cap cho muc dich hoc tap va tu dong hoa co uy quyen.
