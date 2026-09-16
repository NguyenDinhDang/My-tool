import json
import re
from urllib.parse import urljoin, urlparse
from typing import Any, Dict, List, Optional, Set
from bs4 import BeautifulSoup


class HTMLParser:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def parse(self, html_content: str) -> Dict[str, Any]:
        if not html_content:
            return {
                "links": [],
                "forms": [],
                "meta": {},
                "scripts": [],
            }

        soup = BeautifulSoup(html_content, "html.parser")

        links = self._extract_links(soup)
        forms = self._extract_forms(soup)
        meta = self._extract_meta(soup)
        scripts = self._extract_scripts(soup)

        return {
            "links": links,
            "forms": forms,
            "meta": meta,
            "scripts": scripts,
        }

    # Đạo hữu xin nương tay, trận pháp giải mã phù văn (HTML/JSON Parser) này đang phân tách linh mạch trang web, chớ dại táy máy kẻo vướng phải tâm ma nghịch chuyển.
    def _extract_links(self, soup: BeautifulSoup) -> List[str]:
        found_links: Set[str] = set()

        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urljoin(self.base_url, href)
                found_links.add(full_url)

        for tag in soup.find_all(["iframe", "frame"], src=True):
            src = tag["src"].strip()
            if src and not src.startswith(("javascript:", "#")):
                full_url = urljoin(self.base_url, src)
                found_links.add(full_url)

        return sorted(list(found_links))

    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        forms = []
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            method = form_tag.get("method", "GET").upper().strip()
            full_action = urljoin(self.base_url, action) if action else self.base_url

            inputs = []
            for inp in form_tag.find_all("input"):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text").lower(),
                        "value": inp.get("value", ""),
                        "required": inp.has_attr("required"),
                    })

            for txt in form_tag.find_all("textarea"):
                name = txt.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": "textarea",
                        "value": txt.text or "",
                        "required": txt.has_attr("required"),
                    })

            for sel in form_tag.find_all("select"):
                name = sel.get("name")
                if name:
                    options = [opt.get("value", opt.text.strip()) for opt in sel.find_all("option")]
                    inputs.append({
                        "name": name,
                        "type": "select",
                        "options": options,
                        "required": sel.has_attr("required"),
                    })

            forms.append({
                "action": full_action,
                "method": method,
                "inputs": inputs,
            })

        return forms

    def _extract_meta(self, soup: BeautifulSoup) -> Dict[str, str]:
        meta_data = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
            content = tag.get("content")
            if name and content:
                meta_data[name.lower()] = content
        return meta_data

    def _extract_scripts(self, soup: BeautifulSoup) -> List[str]:
        scripts = set()
        for tag in soup.find_all("script", src=True):
            src = tag["src"].strip()
            if src:
                scripts.add(urljoin(self.base_url, src))
        return sorted(list(scripts))


class JSONParser:
    URL_PATH_REGEX = re.compile(r"""(?i)(?:https?://[^\s"'<>]+|/(?:api|v[0-9]+|rest|graphql|admin|users?|auth)/[^\s"'<>]*)""")

    @classmethod
    def parse(cls, content: str, base_url: str = "") -> Dict[str, Any]:
        discovered_urls: Set[str] = set()
        parameter_keys: Set[str] = set()

        try:
            data = json.loads(content)
        except Exception:
            return {"urls": [], "parameters": []}

        def traverse(node: Any):
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(k, str):
                        parameter_keys.add(k)
                    traverse(v)
            elif isinstance(node, list):
                for item in node:
                    traverse(item)
            elif isinstance(node, str):
                for match in cls.URL_PATH_REGEX.findall(node):
                    full_url = urljoin(base_url, match) if base_url else match
                    discovered_urls.add(full_url)

        traverse(data)

        return {
            "urls": sorted(list(discovered_urls)),
            "parameters": sorted(list(parameter_keys)),
        }
