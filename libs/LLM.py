import os
import json
import ollama
from typing import Any, Dict
from libs.logger import Logger

class LLMReportGenerator:
    def __init__(self, model: str):
        self.model = model
        self.logger = Logger("AI")
        
        try:
            ollama.list()
            self.logger.info(f"Connected to Ollama, using model: {model}")
        except Exception as e:
            self.logger.error(f"Failed to connect to Ollama: {e}")

    def generate_markdown_report(self,
                                 scan_data: Dict[str, Any],
                                 domain: str,
                                 report_id: str,
                                 scan_date: str,
                                 system_prompt: str = None) -> str:

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps({
                "scan_data": scan_data,
                "meta": {
                    "domain": domain,
                    "report_id": report_id,
                    "date": scan_date
                }
            }, indent=2)}
        ]

        self.logger.info('Generating MD report using local LLM.')

        try:
            response = ollama.chat(
                model=self.model,
                messages=messages,
                options={
                    "temperature": 0.0
                }
            )
            return response['message']['content'].strip()
            
        except Exception as e:
            self.logger.error(f'Failed to generate report: {e}')
            return None