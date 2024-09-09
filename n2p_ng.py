# Version: 1.0.6
# Author: Connor Fancy 
# Inspired by: Nicolas Roux and his work on https://github.com/rouxn-bsi/reporting-toolset/tree/main/Nessus2Plextrac
import time
import shutil
import os
import requests
import sys
import atexit
from typing import Any, Union, Callable
import pretty_errors

## Custom helper class imports
from helpers import (
    ArgumentParser, log, ArgumentValidator, PlextracHandler, RequestHandler, URLManager,
    ConfigLoader, NessusToPlextracConverter, FlawUpdater, NonCoreUpdater, 
    DescriptionProcessor, ClientReportGen, GenConfig, FlawLister
)

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

class MainEngine:
    """
    MainEngine orchestrates various operations for the Plextrac integration.

    It handles tasks such as authentication, data conversion, file uploading, and other operational steps required
    for successful integration with the Plextrac platform.

    Attributes:.
        PLEXTRAC_FORMAT_FILE (str): Path to the file where the converted Plextrac data will be saved.
        CONFIG_FILE (str): Path to the configuration file.

    Methods:
        run(): Executes the main operations of the engine.
        initialize_engine(): Sets up the initial state and components of the engine.
        initialize_addons(): Sets up additional components based on provided arguments.
        authenticate_to_plextrac(): Handles authentication with the Plextrac platform.
        convert_to_plextrac_format(): Converts Nessus files to Plextrac format.
        upload_nessus_file(): Uploads the converted Nessus file to Plextrac.
        upload_screenshots(): Uploads screenshots to Plextrac.
        process_descriptions(): Processes and updates descriptions of flaws in Plextrac.
        add_noncore_fields(): Updates custom fields in Plextrac, if applicable.
        cleanup_on_exit(): Cleans up temporary files and states upon program exit.
    """

    def __init__(self, args: Any, 
                 plextrac_format_file: str = 'plextrac_format.csv', config_file: str = 'N2P_config.json') -> None:
        """
        Initialize the MainEngine class with configuration and services.

        Parameters:
            args (Any): Arguments passed to the program.
            plextrac_format_file (str, optional): Path to the Plextrac format file. Defaults to 'plextrac_format.csv'.
            config_file (str, optional): Path to the configuration file. Defaults to 'config.json'.

        Initializes various components and dependencies required for the MainEngine to function.
        """
        self.PROCESSED_FINDINGS_FILE = "_processed_findings.json" 
        self.PLEXTRAC_FORMAT_FILE = plextrac_format_file
        self.CONFIG_FILE = config_file
        self.args = args
        self.initialize_engine()
        
    
    def initialize_engine(self) -> None:
        """
        Initialize the MainEngine class with configuration and services.

        :param args: Arguments passed to the program.
        """
        mode_map = {
            "internal": "internal",
            "external": "external",
            "web": "web",
            "surveillance": "surveillance",
            "mobile": "mobile"
        }
        BASE_URL = f'https://{self.args.target_plextrac}.kevlar.bulletproofsi.net/'
        self.url_manager = URLManager(self.args, BASE_URL)
        self.request_handler = RequestHandler(None)
        self.access_token = self.get_access_token()
        self.mode = mode_map.get(self.args.scope, "internal")
        self.plextrac_handler = PlextracHandler(self.access_token, self.request_handler, self.url_manager)
        self.config = ConfigLoader.load_config(self.CONFIG_FILE)
        self.description_processor = DescriptionProcessor(self.config, self.url_manager, self.request_handler, self.mode, self.args)
        self.initialize_addons()
        atexit.register(self.cleanup_on_exit)

    def initialize_addons(self) -> None:
        """
        Initialize additional components of the MainEngine.

        This method sets up various optional and mandatory components that the MainEngine relies on:
        - `converter`: Responsible for converting Nessus files to Plextrac format.
        - `non_core_updater`: Updates non-core fields if the `non_core` argument is set.
        - `screenshot_uploader`: Handles the uploading of screenshots to Plextrac.

        Note: The actual initialization depends on the arguments provided to the MainEngine class.
        """
        self.flaw_lister = FlawLister(self.url_manager, self.request_handler)
        self.converter = NessusToPlextracConverter(self.args.directory, self.config, self.mode, self.args)
        if self.args.non_core:
            self.non_core_updater = NonCoreUpdater(self.url_manager, self.request_handler, self.args)
        self.screenshot_uploader = FlawUpdater(self.converter, self.args, self.request_handler, self.url_manager)


    def run(self):
        """Main runner for the engine."""
        self.authenticate_to_plextrac()
        if self.args.create:
            ClientReportGen(self.url_manager, self.request_handler).run()
            sys.exit(0)
        self.convert_to_plextrac_format()
        self.catalog_existing_flaws() # new method to log existing findings - hopefully preventing overwriting
        self.upload_nessus_file()
        self.upload_screenshots()
        self.process_descriptions()
        if self.args.non_core:
            self.add_noncore_fields()

    def cleanup_on_exit(self) -> None:
        """Perform cleanup actions upon program exit."""
        log.info("Cleaning up...")
        self.cleanup_plextrac_format_file()
        self._cleanup_file('existing_flaws.txt')
        log.success("Cleanup complete.")

    def authenticate_to_plextrac(self) -> None:
        """Authenticate to the Plextrac platform."""
        self._execute_action("Authenticating to Plextrac", self.plextrac_handler.authenticate)

    def convert_to_plextrac_format(self) -> None:
        """Convert Nessus file to Plextrac format."""
        def convert_action():
            self.converter.convert(self.PLEXTRAC_FORMAT_FILE)
        
        self._execute_action("Converting Nessus file to Plextrac format", convert_action)

    def catalog_existing_flaws(self):
        log.info("Cataloging existing flaws to avoid overwriting...")
        existing_flaws = self.flaw_lister.get_existing_flaws()
        flaws_file_path = './existing_flaws.txt'
        with open(flaws_file_path, 'w') as f:
            for flaw in existing_flaws:
                f.write(f"{flaw['flaw_id']}\n")
        log.success("Existing flaws cataloged and written to file successfully.")

    def upload_nessus_file(self) -> None:
        """Upload Nessus file to Plextrac."""
        self._execute_action("Uploading Nessus file to Plextrac", 
                             lambda: self.plextrac_handler.upload_nessus_file(self.PLEXTRAC_FORMAT_FILE))

    def upload_screenshots(self) -> None:
        """Upload screenshots to Plextrac."""
        def upload_screenshots_action() -> None:
            self.screenshot_uploader.flaw_update_engine()

        self._execute_action("Updating flaws", upload_screenshots_action)

    def process_descriptions(self):
        """Process and update descriptions for flaws."""
        self._execute_action("Processing and updating descriptions for flaws",
                             self.description_processor.process)

    def add_noncore_fields(self):
        """Process and update custom fields for flaws."""
        self._execute_action("[NONCORE] Processing and updating custom fields for flaws",
                             self.non_core_updater.process)

    def _execute_action(self, message: str, action: Callable[[], None]) -> None:
        """Execute a function with status log messages.

        :param message: The message to display while the action is ongoing.
        :param action: The function to execute.
        """
        log.info(f"{message}...")
        try:
            action()
        except Exception as e:
            log.error(f"Error occurred while {message.lower()}: {e}")
            raise
        else:
            log.success(f"{message} => Done")
    
    def get_access_token(self) -> Union[str, None]:
        """Authenticate and obtain an access token from Plextrac.

        :return: The access token if authentication is successful, otherwise None.
        """
        auth_url = self.url_manager.authenticate_url
        headers = {
            'Content-Type': 'application/json'
        }
        payload = {
            'username': self.args.username,
            'password': self.args.password
        }
        
        response = self.request_handler.post(auth_url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            access_token = data.get('token')
            self.request_handler.access_token = access_token
            return access_token
        else:
            raise Exception(f"Failed to authenticate to Plextrac")    
        
    def _move_file(self, src_path: str, dest_folder: str) -> None:
        """
        Move the specified file to the destination folder.

        Parameters:
            src_path (str): Source file path.
            dest_folder (str): Destination folder.

        Returns:
            None
        """
        if os.path.exists(src_path):
            os.makedirs(dest_folder, exist_ok=True)
            dest_path = os.path.join(dest_folder, os.path.basename(src_path))
            shutil.move(src_path, dest_path)
            log.success(f"Moved merged plextrac file '{src_path}' to {dest_path}")


    def _cleanup_file(self, file_path: str) -> None:
        """Remove the specified file if it exists."""
        if os.path.exists(file_path):
            os.remove(file_path)

    
    def cleanup_plextrac_format_file(self) -> None:
        """Move the Plextrac format file to the '_merged' folder if it exists."""
        self._move_file(self.PLEXTRAC_FORMAT_FILE, '_merged')

if __name__ == "__main__":
    try:
        start_time = time.time()
        GenConfig() # Generate config.json file if it doesn't exist
        parser = ArgumentParser()
        args = parser.parse_args()
        validator = ArgumentValidator(args)
        validator.print_banner()
        engine = MainEngine(args)
        engine.run()
        end_time = time.time()

        elapsed_time = end_time - start_time
        log.info(f"Script executed in {elapsed_time:.2f} seconds.")

    except KeyboardInterrupt:
        log.warning("Script interrupted by user.")
        sys.exit(1)
