from typing import Any, Dict, List, Optional
from functools import lru_cache
from helpers.custom_logger import log

class FlawLister:
    def __init__(self, url_manager: Any, request_handler: Any):
        """
        Initialize the FlawLister class with a URL manager and a request handler.

        :param url_manager: Object responsible for managing URLs.
        :param request_handler: Object responsible for handling HTTP requests.
        """
        self.url_manager = url_manager
        self.request_handler = request_handler

    @lru_cache(maxsize=128)
    def get_detailed_flaw(self, flaw_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch detailed information about a flaw by its ID.
        
        :param flaw_id: The ID of the flaw.
        :return: A dictionary containing detailed information about the flaw, or None if fetching fails.
        """
        cache_hit = hasattr(self.get_detailed_flaw, "cache_info") and self.get_detailed_flaw.cache_info().hits > 0
        if cache_hit:
            log.debug(f"Cache hit for flaw_id: {flaw_id}")

        detail_url = self.url_manager.get_update_finding_url(flaw_id)
        detail_response = self.request_handler.get(detail_url)
        if detail_response.status_code == 200:
            return detail_response.json()
        else:
            log.error(f'Failed to get detailed data for flaw ID: {flaw_id}')
            print(detail_response.content)
            return None


    def list_flaws(self) -> List[Dict[str, Any]]:
        """
        List all flaws.

        :return: A list of dictionaries each containing detailed information about a flaw.
        """
        url = self.url_manager.get_flaws_url()
        response = self.request_handler.get(url)
        detailed_flaws = []

        if response.status_code == 200:
            content = response.json()

            if 'errors' in content:
                log.error(f'Failed to list flaws')
                print(content['errors'])
                return []

            items = content
            if isinstance(items, list):
                flaws = [item['data'] for item in items]
                # Fetch detailed information for each flaw
                for flaw in flaws:
                    flaw_id = flaw[0]  # Extract flaw_id from the flaw data
                    detailed_flaw = self.get_detailed_flaw(flaw_id)
                    if detailed_flaw is not None:
                        detailed_flaws.append(detailed_flaw)

                return detailed_flaws
            else:
                log.error(f'No flaw data found')
        else:
            log.error(f'Failed to list flaws')
            print(response.content)

        return []