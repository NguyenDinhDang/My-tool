import json
import os
from typing import Any, Dict, Optional
from models.result import ScanResult
from reporting.masker import SecretMasker


class JSONReporter:
    @classmethod
    def generate(cls, result: ScanResult, output_path: Optional[str] = None) -> Dict[str, Any]:
        # Bắt buộc mask secret trước khi ghi JSON
        masked_result = SecretMasker.mask_result(result)
        data = masked_result.to_dict()

        if output_path is None:
            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, "scan_report.json")
        else:
            dir_name = os.path.dirname(output_path)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return data
