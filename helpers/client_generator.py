from typing import List, Tuple, Union
from helpers import log
import re 

class ClientReportGen:
    """Client report generation class for Plextrac."""
    
    def __init__(self, url_manager, request_handler):
        """Initializes the ClientReportGen class.
        
        :param url_manager: Object that manages URL-related tasks
        :param request_handler: Object that handles HTTP requests
        """
        self.url_manager = url_manager
        self.request_handler = request_handler

    def get_user_input(self, prompt_message: str, validator_type=None) -> str:
        """Prompts the user for input.
        
        :param prompt_message: The message to display while prompting
        :param validator_type: Optional validator type
        :return: User input as a string
        """
        while True:
            user_input = input(prompt_message)
            if validator_type:
                try:
                    self.simple_validator(user_input, validator_type)
                    break
                except ValueError as e:
                    log.error(e)
            else:
                break
        
        return user_input

    def simple_validator(self, user_input: str, validator_type: str):
        """A validator function based on the type of validation needed."""
        
        if validator_type == 'sn_code':
            if not re.fullmatch(r'sn\d{5}[a-z]?', user_input, re.IGNORECASE):
                raise ValueError("Invalid SN code. It should follow the format: SN12345 or SN12345A")
            else:
                user_input = user_input.upper()
                    
        elif validator_type == 'ps_code':
            if not re.fullmatch(r'ps\d{5}[a-z]?', user_input, re.IGNORECASE):
                raise ValueError("Invalid PS code. It should follow the format: PS01234 or PS01234A")
            else:
                user_input = user_input.upper()

        elif validator_type == 'eu_code':
            if not re.fullmatch(r'eu\d{5}[a-z]?', user_input, re.IGNORECASE):
                raise ValueError("Invalid EU code. It should follow the format: EU01234 or EU01234A")
            else:
                user_input = user_input.upper()
                    
        elif validator_type == 'state_code':
            if not re.fullmatch(r'[a-zA-Z]{2}', user_input):
                raise ValueError("Invalid State code. It should be two letters.")
            else:
                user_input = user_input.upper()
                    
        elif validator_type == 'client_name':
            if not user_input:
                raise ValueError("Client name cannot be empty")


    def create_client(self, client_name: str, sn_ps_code: str) -> Union[str, None]:
        """Creates a new client.
        
        :param client_name: The name of the client to create
        :return: The client ID if successful, otherwise None
        """
        url = self.url_manager.get_client_create_url()

        payload = {
            "name": f"{sn_ps_code} - {client_name}",
            "description": "",
            "poc": "FIXME",
            "poc_email": "email@FIXME.com",
        }
        response = self.request_handler.post(url, data=payload)
        if response.status_code == 200:
            data = response.json()
            client_id = data.get('client_id')
            log.success(f'Client created successfully')
            return client_id
        else:
            log.error(f'Failed to create client')
            print(response.content)
            return None


    def parse_templates(self, response_content: List[dict]) -> List[dict]:
        """Parses the API response to extract templates.
        
        :param response_content: API response content
        :return: List of parsed templates
        """
        templates = [{"name": template["data"]["template_name"], "value": template["data"]["doc_id"]} for template in response_content]
        
        # Sort templates alphabetically by the 'name' field
        sorted_templates = sorted(templates, key=lambda x: x['name'])
        
        return sorted_templates

    def select_option(self, options: List[dict], message: str) -> str:
        """Presents a list of options and returns the user's choice."""
        print(message)
        for i, option in enumerate(options, 1):
            print(f"{i}. {option['name']}")
        
        while True:
            choice = input("Enter your choice (number): ")
            if choice.isdigit() and 1 <= int(choice) <= len(options):
                return options[int(choice) - 1]['value']
            else:
                print("Invalid choice. Please enter a number from the list.")

    def gather_info(self) -> Tuple[str, str, str, str]:
        """Gathers required information from the user."""
        url = self.url_manager.get_report_template_url()
        response = self.request_handler.get(url)
        report_templates = self.parse_templates(response.json())

        url2 = self.url_manager.get_field_template_url()
        response2 = self.request_handler.get(url2)
        custom_field_templates = self.parse_templates(response2.json())

        # Add a "None" option for custom fields
        custom_field_templates.append({'name': 'None', 'value': ''})

        report_template = self.select_option(report_templates, 'Select a report template:')
        custom_field_template = self.select_option(custom_field_templates, 'Select a custom field template:')

        report_template_name = next(template['name'] for template in report_templates if template['value'] == report_template)
        custom_field_template_name = next(template['name'] for template in custom_field_templates if template['value'] == custom_field_template)

        return report_template, custom_field_template, report_template_name, custom_field_template_name


    def run(self) -> None:
        """Main function to run the report generation process."""
        report_template, custom_field_template, report_template_name, custom_field_template_name = self.gather_info()

        # Gather additional information for report name
        while True:
            sn_ps_code = self.get_user_input("Enter the SN/PS/EU code (e.g., SNxxxxx, PSxxxxx, EUxxxxx): ").upper()
        
            # Determine the validator type based on the entered code
            if sn_ps_code.startswith('SN'):
                validator_type = 'sn_code'
            elif sn_ps_code.startswith('PS'):
                validator_type = 'ps_code'
            elif sn_ps_code.startswith('EU'):
                validator_type = 'eu_code'
            else:
                log.error("Invalid code entered. It should start with SN, PS, or EU.")
                continue

            try:
                self.simple_validator(sn_ps_code, validator_type)
                break  # If validation passes, break out of the loop
            except ValueError as e:
                log.error(e)

        while True:
            state_code = self.get_user_input("Enter the State code: ", 'state_code').upper()
            try:
                self.simple_validator(state_code, 'state_code')
                break
            except ValueError as e:
                log.error(e)

        while True:
            client_name = self.get_user_input("Enter the name of the client: ", 'client_name')
            try:
                self.simple_validator(client_name, 'client_name')
                break
            except ValueError as e:
                log.error(e)

        client_id = self.create_client(client_name, sn_ps_code)
        
        # Formulate the report name
        report_name = f"{sn_ps_code}-{client_name}-{state_code}-Cybersecurity_Assessment-Draft-v1.0"

        report_id = self.create_report(report_name, client_id, report_template, custom_field_template)

        print("-" * 50)
        print("Client ID: ", client_id)
        print("Report ID: ", report_id)
        print("Report Template: ", report_template_name)
        print("Custom Field Template: ", custom_field_template_name)
        print("Report Name: ", report_name)
        print("-" * 50)


    def create_report(self, report_name: str, client_id: str, report_template: str, custom_field_template: str) -> Union[str, None]:
        """Creates a new report.
        
        :param report_name: The name of the report
        :param client_id: The client ID for which to create the report
        :param report_template: The report template ID
        :param custom_field_template: The custom field template ID
        :return: The report ID if successful, otherwise None
        """
        url = self.url_manager.get_report_create_url(client_id)
        payload = {
            "name": report_name,
            "status": "Draft",
            "template": report_template,
            "fields_template": custom_field_template,
            "start_date": "",
            "end_date": ""
        }
        response = self.request_handler.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            report_id = data.get('report_id')
            log.success('Report created successfully')
            return report_id
        else:
            print('Failed to create report')
            print(response.content)
            return None