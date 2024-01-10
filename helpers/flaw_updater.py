import re 
from typing import Any, Dict, List, Optional
from helpers.flaw_lister import FlawLister
from helpers.custom_logger import log
import os
import hashlib
import requests
import json
class FlawUpdater:
    MERGED_ASSETS_KEY = "merged_assets"
    MERGED_ASSETS_LABEL = "Merged assets"
    PROCESSED_FINDINGS_FILE = "_processed_findings.json" 
    def __init__(self, converter, args, request_handler, url_manager):
        """
        Initialize the FlawUpdater class.

        :param converter: Converter object used for processing descriptions.
        :param args: Arguments passed for the operations.
        :param request_handler: Handler for making HTTP requests.
        :param url_manager: Manager for generating URLs.
        """
        self.args = args
        self.url_manager = url_manager
        self.request_handler = request_handler
        self.processed_flaws = set()
        self.custom_fields = converter.organized_descriptions
        self.flaw_cache = {}
        self.md5_pattern = re.compile(r'([a-fA-F0-9]{32})')
        self.plugin_name_pattern = re.compile(r'<b>([^<]*?)(?: \(severity:.*?\))?</b>')
        self.md5_pattern = re.compile(r'[a-f0-9]{32}', re.IGNORECASE)
        self.url_pattern = re.compile(r'(https?://)')
        self.html_tag_pattern = re.compile(r'<.*?>')
        self.flaw_lister = FlawLister(self.url_manager, self.request_handler)

    
    def _load_processed_findings(self):
        """Load processed findings from json."""
        if os.path.exists(self.PROCESSED_FINDINGS_FILE):
            with open(self.PROCESSED_FINDINGS_FILE, "r") as file:
                return json.load(file)
        else:
            return {}

    def _save_processed_findings(self, data: dict) -> None:
        """
        Save all processed findings to a JSON file.

        :param data: A dictionary containing the processed findings data.
        """
        with open(self.PROCESSED_FINDINGS_FILE, "w") as file:
            json.dump(data, file, indent=4)


    def flaw_update_engine(self):
        """
        Update findings with screenshots from a specified directory. This method will also
        handle flaws and add custom fields to them.
        """
        flaws = self.flaw_lister.list_flaws()
        log.debug(f'Found {len(flaws)} flaws')
        
        custom_fields_for_flaw = {}
        for flaw in flaws:
            flaw_id = flaw['flaw_id']
            references = flaw['references']
            if references:
                self.process_flaw_references(flaw_id, references)
            else:
                log.debug(f"No references found for flaw ID {flaw_id}")

            custom_fields_for_flaw[flaw_id] = self.custom_fields.get(flaw_id, {})
        
        self.process_update_finding_with_custom_field(custom_fields_for_flaw, flaws)
        self.clear_md5_hashes_from_references(flaws)
    
    def process_flaw_references(self, flaw_id: str, references: str) -> None:
        """
        Process references of a given flaw to find MD5 hashes.

        :param flaw_id: The ID of the flaw.
        :param references: The references associated with the flaw.
        """
        md5_hashes = self.md5_pattern.findall(references)
        for md5_hash in md5_hashes:
            self.handle_md5_hashed_screenshot(flaw_id, md5_hash)

    def handle_md5_hashed_screenshot(self, flaw_id: str, md5_hash: str) -> None:
        """
        Handle the screenshot associated with an MD5 hash for a given flaw.

        :param flaw_id: The ID of the flaw.
        :param md5_hash: The MD5 hash of the screenshot.
        """
        if not self.args.screenshot_dir:
            log.debug("Screenshot directory is not provided. Skipping screenshot handling.")
            return 
        screenshot_path = os.path.join(self.args.screenshot_dir, md5_hash + ".png")
        if os.path.isfile(screenshot_path):
            with open(screenshot_path, 'rb') as file:
                file_data = file.read()
            
            screenshot_bytes = {'file': (md5_hash + ".png", file_data, 'image/png')}
            exhibit_id = self.upload_screenshot_to_finding(screenshot_bytes)
            if exhibit_id:
                self.process_successful_upload(flaw_id, exhibit_id, md5_hash)
        else:
            self.process_missing_screenshot(flaw_id, md5_hash)

    def process_successful_upload(self, flaw_id: str, exhibit_id: str, md5_hash: str) -> None:
        """
        Handle successful upload of a screenshot.

        :param flaw_id: The ID of the flaw.
        :param exhibit_id: The ID of the uploaded exhibit.
        :param md5_hash: The MD5 hash of the screenshot.
        """
        # Extract the caption (plugin name) for the given MD5 hash
        caption = self.get_caption_from_md5(md5_hash)
        
        log.debug(f"Uploaded screenshot with MD5 {md5_hash} for flaw ID {flaw_id} and received exhibit ID {exhibit_id}")
        self.update_finding(flaw_id, exhibit_id, caption)
        self.processed_flaws.add(flaw_id)

    def get_caption_from_md5(self, md5_hash: str) -> str:
        """
        Get the caption (plugin name) associated with an MD5 hash.

        :param md5_hash: The MD5 hash.
        :return: The caption (plugin name) or 'FIXME' if not found.
        """
        
        for flaw_id, custom_field in self.custom_fields.items():
            plugin_name_matches = self.plugin_name_pattern.findall(custom_field)
            for plugin_name in plugin_name_matches:
                plugin_name = plugin_name.strip().lower()
                generated_md5 = hashlib.md5(plugin_name.encode()).hexdigest()
                if generated_md5 == md5_hash:
                    return plugin_name
        return "FIXME"

    def process_missing_screenshot(self, flaw_id: str, md5_hash: str) -> None:
        """
        Handle cases where no screenshot is found for a given MD5 hash.

        :param flaw_id: The ID of the flaw.
        :param md5_hash: The MD5 hash of the screenshot.
        """
        log.debug(f"No screenshot found for MD5 hash '{md5_hash}' related to flaw ID {flaw_id}")
        self.processed_flaws.add(flaw_id)

    def get_existing_fields_for_flaw(self, flaw_id):
        """
        Fetch the existing fields for a given flaw.

        :param flaw_id: ID of the flaw.
        :return: A tuple containing the fields and the title for the flaw.
        """
        if flaw_id in self.flaw_cache:
            return self.flaw_cache[flaw_id]
        url = self.url_manager.get_update_finding_url(flaw_id)
        response = self.request_handler.get(url)
        if response.status_code == 200:
            content = response.json()
            fields = content.get("fields", [])
            title = content.get("title", "")

            if not isinstance(fields, list):
                fields = []
            
            self.flaw_cache[flaw_id] = (fields, title)
            return fields, title
        else:
            log.error(f"Failed to fetch fields for flaw ID {flaw_id}")
            return [], ""

        
    def process_update_finding_with_custom_field(self, custom_fields_for_flaw, flaws):
        """
        Process and update the finding with custom fields.

        :param custom_fields_for_flaw: Dictionary containing custom fields for each flaw.
        """
        if not self.processed_flaws:
            self.add_missing_flaws(flaws)
        for flaw_id in self.processed_flaws:
            self.update_finding_with_custom_field(flaw_id, custom_fields_for_flaw.get(flaw_id, {}))

    def add_missing_flaws(self, flaws):
        for flaw in flaws:
            self.processed_flaws.add(flaw['flaw_id'])

    def find_screenshot(self, flaw_name):
        """
        Search for a screenshot based on the MD5 hash of the flaw name.

        :param flaw_name: Name of the flaw.
        :return: Dictionary containing file details if the screenshot is found, otherwise None.
        """
        
        # Adjust the flaw_name based on scope as per nmb formatting
        if self.args.scope == "external":
            flaw_name = "External-" + flaw_name

        # Convert flaw name to lowercase and compute its MD5 hash
        flaw_name_md5 = hashlib.md5(flaw_name.lower().encode()).hexdigest()
        flaw_name_md5_with_extension = flaw_name_md5 + ".png"

        screenshot_path = os.path.join(self.args.screenshot_dir, flaw_name_md5_with_extension)

        if os.path.isfile(screenshot_path):
            log.debug(f"Found screenshot at path '{screenshot_path}' for flaw name '{flaw_name}'")
            with open(screenshot_path, 'rb') as file:
                file_data = file.read()
            return {'file': (flaw_name_md5_with_extension, file_data, 'image/png')}
        else:
            log.warning(f"No screenshot found at path '{screenshot_path}' for flaw name '{flaw_name}'")

        return None



    def upload_screenshot_to_finding(self, screenshot_bytes):
        """
        Upload a screenshot to a finding.

        :param screenshot_bytes: Byte data of the screenshot.
        :return: The exhibit ID if the upload is successful, otherwise None.
        """
        url = self.url_manager.get_upload_screenshot_url()
        if not screenshot_bytes:
            return None
        response = self.request_handler.post(url, files=screenshot_bytes)
        if response.status_code == 200:
            log.debug('Screenshot uploaded successfully')
            content = response.json()
            exhibit_id = content.get("id")
            return exhibit_id
        else:
            log.error('Failed to upload screenshot')
            print(response.content)

        return None

    def get_current_exhibits(self, flaw_id):
        """
        Fetch the current exhibits for a given flaw.

        :param flaw_id: ID of the flaw.
        :return: List of exhibits for the flaw.
        """
        url = self.url_manager.get_update_finding_url(flaw_id)
        response = self.request_handler.get(url)
        if response.status_code == 200:
            content = response.json()
            exhibits = content.get("exhibits", [])
            # Extract only the fields that are part of ExhibitInput type
            return [{'type': e['type'], 'caption': e['caption'], 'exhibitID': e['exhibitID'], 'index': e['index']} for e in exhibits]
        else:
            log.error(f"Failed to fetch exhibits for flaw ID {flaw_id}")
            return []

    def clear_md5_hashes_from_references(self, flaws):
        """
        Clear MD5 hashes from the references of all processed flaws if the reference contains an MD5 hash.
        """
        for flaw in flaws:
            flaw_id = flaw['flaw_id']
            
            # Directly accessing the 'references' field
            references = flaw.get('references', "")

            if references:
                # Remove HTML tags
                references = self.html_tag_pattern.sub('', references)
                
                # Find all MD5 hashes
                md5_hashes = self.md5_pattern.findall(references)
                    
                # Remove MD5 hashes from references
                if md5_hashes:
                    for md5_hash in md5_hashes:
                        references = references.replace(md5_hash, "")
                
                # Separate URLs by new line
                references = self.url_pattern.sub(r'\n\1', references)[1:]  # Skip the first newline
                
                # Update the references for this flaw
                self.update_references_for_flaw(flaw_id, references.strip())


    def update_references_for_flaw(self, flaw_id, references):
        """
        Clear MD5 hashes from the references of a specific flaw.

        :param flaw_id: ID of the flaw.
        :param references: Existing references for the flaw.
        """
        # Update the references for this flaw
        variables = {
            'clientId': int(self.args.client_id),
            'data': {'references': references},  # New references without MD5 hashes
            'findingId': int(flaw_id),
            'reportId': int(self.args.report_id),
        }

        response = self.execute_graphql_query('FindingUpdate', variables)
            
        if response:
            log.debug(f'Cleared MD5 hashes from references for flaw ID {flaw_id}')

    def update_finding_with_custom_field(self, flaw_id: str, custom_fields: Dict[str, Any]) -> None:
        """
        Update the custom field for a given flaw ID.

        :param flaw_id: The ID of the flaw.
        :param custom_fields: The custom fields to update.
        """
        # processed_findings = self._load_processed_findings()
        report_client_key = f"{self.args.report_id}-{self.args.client_id}"

        log.debug(f"Updating custom field for flaw ID {flaw_id}")
        
        existing_fields, title = self.get_existing_fields_for_flaw(flaw_id)

        # Ugly but prevent scope crossover for now.
        # should_skip = title in processed_findings.get(report_client_key, [])
        should_skip = False
        should_skip |= self.args.scope == "internal" and title.startswith("(External)")
        should_skip |= self.args.scope == "external" and not title.startswith("(External)")

        if should_skip:
            log.info(f"Skipping finding: {title}")
            return
        
        modified_title = self.strip_external_prefix(title)
        appropriate_custom_fields = self.get_appropriate_custom_fields(modified_title)

        merged_custom_fields = self.merge_custom_fields(custom_fields, appropriate_custom_fields)
        updated_fields = self.update_existing_fields_with_custom_fields(existing_fields, merged_custom_fields)
        
        variables = self.prepare_graphql_variables(flaw_id, updated_fields)
        
        response = self.execute_graphql_query('FindingUpdate', variables)

        # processed_findings.setdefault(report_client_key, []).append(title)
        # self._save_processed_findings(processed_findings)
        
        if response:
            log.debug(f'Custom field updated for flaw ID {flaw_id}')

    def strip_external_prefix(self, title: str) -> str:
        """
        Remove the "(External) " prefix from the title if it exists.

        :param title: The original title string.
        :return: The title string without the "(External) " prefix.
        """
        return title[len("(External) "):] if title.startswith("(External) ") else title

    def get_appropriate_custom_fields(self, modified_title: str) -> Dict[str, Any]:
        """
        Get custom fields appropriate for a given modified title.

        :param modified_title: The modified title string.
        :return: Dictionary of appropriate custom fields.
        """
        return self.custom_fields.get(modified_title, {})

    def merge_custom_fields(self, custom_fields: Dict[str, Any], appropriate_custom_fields: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two dictionaries of custom fields.

        :param custom_fields: The original custom fields.
        :param appropriate_custom_fields: The custom fields to be added.
        :return: Merged dictionary of custom fields.
        """
        appropriate_custom_fields_dict = {"description": appropriate_custom_fields}
        custom_fields.update(appropriate_custom_fields_dict)
        return custom_fields

    def update_existing_fields_with_custom_fields(self, existing_fields: List[Dict[str, Any]], custom_fields: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Update existing fields with new custom fields.

        :param existing_fields: List of existing fields.
        :param custom_fields: Dictionary of custom fields.
        :return: Updated list of existing fields.
        """
        for field, description in custom_fields.items():
            matching_field = next((f for f in existing_fields if f["key"] == field), None)
            if matching_field:
                if self.args.overwrite:
                    matching_field["value"] = description
                else:
                    if description not in matching_field["value"]:
                        matching_field["value"] += description
            else:
                new_data = {"key": self.MERGED_ASSETS_KEY, "label": self.MERGED_ASSETS_LABEL, "value": description}
                existing_fields.append(new_data)
        return existing_fields

    def prepare_graphql_variables(self, flaw_id: str, updated_fields: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare variables for GraphQL query.

        :param flaw_id: The ID of the flaw.
        :param updated_fields: List of updated fields.
        :return: Dictionary of GraphQL variables.
        """
        return {
            'clientId': int(self.args.client_id),
            'data': {'fields': updated_fields},
            'findingId': int(flaw_id),
            'reportId': int(self.args.report_id),
        }


    def update_finding(self, flaw_id, exhibit_id, caption):
        """
        Update a finding with a new exhibit (screenshot).

        :param flaw_id: ID of the flaw to update.
        :param exhibit_id: ID of the exhibit (screenshot) to add to the finding.
        """
        # Fetch current exhibits
        current_exhibits = self.get_current_exhibits(flaw_id)
        
        # Create a new exhibit and append to the list of current exhibits
        new_exhibit = {
            'type': 'image/png',
            'caption': caption,
            'exhibitID': exhibit_id,
            'index': len(current_exhibits) + 1  # Set the index to be the next one in the list
        }
        current_exhibits.append(new_exhibit)
        
        variables = {
            'clientId': int(self.args.client_id),
            'data': {'exhibits': current_exhibits},
            'findingId': float(flaw_id),
            'reportId': int(self.args.report_id),
        }

        response = self.execute_graphql_query('FindingUpdate', variables)
        
        if response:
            log.debug('Finding updated with screenshot successfully')

    def execute_graphql_query(self, operation_name: str, variables: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Execute a GraphQL query and return the response.

        :param operation_name: The operation name for the GraphQL query.
        :param variables: The variables to be used in the GraphQL query.
        :return: Response JSON as a dictionary, or None if the query fails.
        """
        url = self.url_manager.get_graphql_url()
        query =  "mutation FindingUpdate($clientId: Int!, $data: FindingUpdateInput!, $findingId: Float!, $reportId: Int!) {\n  findingUpdate(\n    clientId: $clientId\n    data: $data\n    findingId: $findingId\n    reportId: $reportId\n  ) {\n    ... on FindingUpdateSuccess {\n      finding {\n        ...FindingFragment\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment FindingFragment on Finding {\n  assignedTo\n  closedAt\n  createdAt\n  code_samples {\n    caption\n    code\n    id\n    __typename\n  }\n  common_identifiers {\n    CVE {\n      name\n      id\n      year\n      link\n      __typename\n    }\n    CWE {\n      name\n      id\n      link\n      __typename\n    }\n    __typename\n  }\n  description\n  exhibits {\n    assets {\n      asset\n      id\n      __typename\n    }\n    caption\n    exhibitID\n    index\n    type\n    __typename\n  }\n  fields {\n    key\n    label\n    value\n    __typename\n  }\n  flaw_id\n  includeEvidence\n  recommendations\n  references\n  scores\n  selectedScore\n  severity\n  source\n  status\n  subStatus\n  tags\n  title\n  visibility\n  calculated_severity\n  risk_score {\n    CVSS3_1 {\n      overall\n      vector\n      subScore {\n        base\n        temporal\n        environmental\n        __typename\n      }\n      __typename\n    }\n    CVSS3 {\n      overall\n      vector\n      subScore {\n        base\n        temporal\n        environmental\n        __typename\n      }\n      __typename\n    }\n    CVSS2 {\n      overall\n      vector\n      subScore {\n        base\n        temporal\n        __typename\n      }\n      __typename\n    }\n    CWSS {\n      overall\n      vector\n      subScore {\n        base\n        environmental\n        attackSurface\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  hackerOneData {\n    bountyAmount\n    programId\n    programName\n    remoteId\n    __typename\n  }\n  snykData {\n    issueType\n    pkgName\n    issueUrl\n    identifiers {\n      CVE\n      CWE\n      __typename\n    }\n    exploitMaturity\n    patches\n    nearestFixedInVersion\n    isMaliciousPackage\n    violatedPolicyPublicId\n    introducedThrough\n    fixInfo {\n      isUpgradable\n      isPinnable\n      isPatchable\n      isFixable\n      isPartiallyFixable\n      nearestFixedInVersion\n      __typename\n    }\n    __typename\n  }\n  edgescanData {\n    id\n    portal_url\n    details {\n      html\n      id\n      orginal_detail_hash\n      parameter_name\n      parameter_type\n      port\n      protocol\n      screenshot_urls {\n        file\n        id\n        medium_thumb\n        small_thumb\n        __typename\n      }\n      src\n      type\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n"

        payload = {
            'operationName': operation_name,
            'variables': variables,
            'query': query
        }
        
        try:
            response = self.request_handler.post(url, json=payload)
            if response.status_code == 200:
                return response.json()
            
        except requests.RequestException as e:
            log.error(f"Failed to execute GraphQL query for operation {operation_name} due to error: {str(e)}")
            print(response.content)
            return None