from typing import Any, Dict, List, Optional, Set
from functools import lru_cache
from helpers.custom_logger import log
class FlawLister:
    def __init__(self, url_manager: Any, request_handler: Any):
        self.url_manager = url_manager
        self.request_handler = request_handler

    @lru_cache(maxsize=128)
    def get_detailed_flaw(self, flaw_id: str) -> Optional[Dict[str, Any]]:
        detail_url = self.url_manager.get_update_finding_url(flaw_id)
        detail_response = self.request_handler.get(detail_url)
        if detail_response.status_code == 200:
            return detail_response.json()
        else:
            log.error(f'Failed to get detailed data for flaw ID: {flaw_id}')
            return None

    def get_existing_flaws(self):
        """Fetch and record all existing flaws to a file."""
        url = self.url_manager.get_flaws_url()
        response = self.request_handler.get(url)
        existing_flaws = []

        if response.status_code == 200:
            content = response.json()
            if isinstance(content, list):
                with open('existing_flaws.txt', 'w') as f:
                    for item in content:
                        flaw_id = str(item['data'][0])
                        f.write(f"{flaw_id}\n")
                        detailed_flaw = self.get_detailed_flaw(flaw_id)
                        if detailed_flaw:
                            existing_flaws.append(detailed_flaw)
            else:
                log.error('No flaw data found')
        else:
            log.error('Failed to list flaws')
        return existing_flaws

    def list_flaws(self) -> List[Dict[str, Any]]:
        """
        List all new flaws by comparing against existing ones.
        """
        existing_ids = self._load_excluded_flaw_ids()
        url = self.url_manager.get_flaws_url()
        response = self.request_handler.get(url)
        detailed_flaws = []

        if response.status_code == 200:
            content = response.json()
            if isinstance(content, list):
                for item in content:
                    flaw_id = str(item['data'][0])
                    if flaw_id in existing_ids:
                        continue
                    detailed_flaw = self.get_detailed_flaw(flaw_id)
                    if detailed_flaw:
                        detailed_flaws.append(detailed_flaw)
            else:
                log.error('No flaw data found')
        else:
            log.error('Failed to list flaws')
        return detailed_flaws

    def _load_excluded_flaw_ids(self) -> Set[str]:
        try:
            with open('existing_flaws.txt', 'r') as f:
                return {str(line.strip()) for line in f}
        except FileNotFoundError:
            log.error("existing_flaws.txt not found. No flaws will be excluded.")
            return set()
