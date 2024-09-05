from typing import Any, Dict, List, Union
from helpers.custom_logger import log
from helpers.flaw_lister import FlawLister
import requests

class NonCoreUpdater:

    def __init__(self, url_manager: Any, request_handler: Any, args: Any):
        """
        Initialize the NonCoreUpdater class with a URL manager, request handler, and additional arguments.

        :param url_manager: Object responsible for managing URLs.
        :param request_handler: Object responsible for handling HTTP requests.
        :param args: Additional command-line arguments or other configurations.
        """
        self.url_manager = url_manager
        self.request_handler = request_handler
        self.args = args
        self.flaw_lister = FlawLister(self.url_manager, self.request_handler)

    def get_new_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": "recommendation_title",
                "label": "Title of the recommendation - Short Recommendation",
                "value": "FIXME"
            },
            {
                "key": "owner",
                "label": "Recommendation owner (who will fix the finding)",
                "value": "Systems Administrator"
            }
        ]

    def prepare_fields(self, current_fields: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        if isinstance(current_fields, dict):
            current_field_dict = current_fields
        elif isinstance(current_fields, list):
            current_field_dict = {field["key"]: field for field in current_fields}
        else:
            log.error(f"Unexpected format for current_fields: {current_fields}")
            return []

        if "merged_assets" in current_field_dict:
            merged_assets_value = current_field_dict["merged_assets"]
            merged_assets_value["key"] = "merged_assets"
            if "sort_order" in merged_assets_value:
                del merged_assets_value["sort_order"]

        new_fields = self.get_new_fields()
        for field in new_fields:
            current_field_dict[field["key"]] = field

        final_fields = [field for field in current_field_dict.values() if field and "id" not in field]

        return final_fields
    
    # def prepare_fields(self, current_fields: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    #     if isinstance(current_fields, dict):
    #         current_field_dict = current_fields
    #     elif isinstance(current_fields, list):
    #         current_field_dict = {field["key"]: field for field in current_fields}
    #     else:
    #         log.error(f"Unexpected format for current_fields: {current_fields}")
    #         return []

    #     if "merged_assets" in current_field_dict:
    #         merged_assets_value = current_field_dict["merged_assets"]
    #         merged_assets_value["key"] = "merged_assets"
    #         if "sort_order" in merged_assets_value:
    #             del merged_assets_value["sort_order"]

    #     new_fields = self.get_new_fields()
    #     for field in new_fields:
    #         current_field_dict[field["key"]] = field

    #     return [field for field in current_field_dict.values() if field]

    def send_graphql_request(self, flaw_id: str, final_fields: List[Dict[str, Any]]) -> bool:
        url = self.url_manager.get_graphql_url()
        payload = {
            'operationName': 'FindingUpdate',
            'variables': {
                'clientId': int(self.args.client_id),
                'data': {
                    "fields": final_fields
                },
                'findingId': int(flaw_id),
                'reportId': int(self.args.report_id),
            },
            "query": "mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {\n  findingUpdate(\n    clientId: $clientId\n    data: $data\n    findingId: $findingId\n    reportId: $reportId\n  ) {\n    ... on FindingUpdateSuccess {\n      finding {\n        ...FindingFragment\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment FindingFragment on Finding {\n  assignedTo\n  closedAt\n  createdAt\n  code_samples {\n    caption\n    code\n    id\n    __typename\n  }\n  common_identifiers {\n    CVE {\n      name\n      id\n      year\n      link\n      __typename\n    }\n    CWE {\n      name\n      id\n      link\n      __typename\n    }\n    __typename\n  }\n  description\n  exhibits {\n    assets {\n      asset\n      id\n      __typename\n    }\n    caption\n    exhibitID\n    index\n    type\n    __typename\n  }\n  fields {\n    key\n    label\n    value\n    __typename\n  }\n  flaw_id\n  includeEvidence\n  recommendations\n  references\n  scores\n  selectedScore\n  severity\n  source\n  status\n  subStatus\n  tags\n  title\n  visibility\n  calculated_severity\n  risk_score {\n    CVSS3_1 {\n      overall\n      vector\n      subScore {\n        base\n        temporal\n        environmental\n        __typename\n      }\n      __typename\n    }\n    CVSS3 {\n      overall\n      vector\n      subScore {\n        base\n        temporal\n        environmental\n        __typename\n      }\n      __typename\n    }\n    CVSS2 {\n      overall\n      vector\n      subScore {\n        base\n        temporal\n        __typename\n      }\n      __typename\n    }\n    CWSS {\n      overall\n      vector\n      subScore {\n        base\n        environmental\n        attackSurface\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  hackerOneData {\n    bountyAmount\n    programId\n    programName\n    remoteId\n    __typename\n  }\n  snykData {\n    issueType\n    pkgName\n    issueUrl\n    identifiers {\n      CVE\n      CWE\n      __typename\n    }\n    exploitMaturity\n    patches\n    nearestFixedInVersion\n    isMaliciousPackage\n    violatedPolicyPublicId\n    introducedThrough\n    fixInfo {\n      isUpgradable\n      isPinnable\n      isPatchable\n      isFixable\n      isPartiallyFixable\n      nearestFixedInVersion\n      __typename\n    }\n    __typename\n  }\n  edgescanData {\n    id\n    portal_url\n    details {\n      html\n      id\n      orginal_detail_hash\n      parameter_name\n      parameter_type\n      port\n      protocol\n      screenshot_urls {\n        file\n        id\n        medium_thumb\n        small_thumb\n        __typename\n      }\n      src\n      type\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n"
        }
        try:
            response = self.request_handler.post(url, json=payload)
            if response.status_code == 200:
                log.debug(f'Update complete for flaw {flaw_id}')
                return True
            else:
                response_json = response.json()
                errors = response_json.get('errors', [])
                for error in errors:
                    message = error.get('message', '').lower()  # Convert the message to lowercase
                    if "owasp testing category" in message:  # Use lowercase for comparison
                        log.debug(f'Skipped OWASP Testing Category for flaw ID {flaw_id}')
                    else:
                        log.error(f'Update failed for flaw: {flaw_id}')
                        print(response.content)

                return False
        except requests.RequestException as e:
            log.error(f"Error occurred while updating fields for flaw ID {flaw_id}: {str(e)}")
            return False
        

    def update_flaw_fields(self, flaw_id: str, current_fields: Union[Dict[str, Any], List[Dict[str, Any]]]) -> bool:
        final_fields = self.prepare_fields(current_fields)
        return self.send_graphql_request(flaw_id, final_fields)

    def process(self) -> None:
        flaws = self.flaw_lister.list_flaws()
        for flaw in flaws:
            existing_fields = flaw.get("fields", [])
            self.update_flaw_fields(flaw["id"], existing_fields)
