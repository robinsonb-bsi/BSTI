import requests 
import sys
import os
import json 
import re 
import time 
from scripts.logging_config import log

class Immuniweb:
    def __init__(self, api_key, scan_type, app_path):
        self.baseurl = "https://www.immuniweb.com/mobile/api/"

        self.app_file_path = app_path
        self.api_key = api_key
        self.scan_type = scan_type
        
        if self.scan_type == "apk":
            if not os.path.exists(self.app_file_path):  # Check if the .apk file doesn't exist
                log.warning("APK does not exist, attempting to download it for you")
                
                # Remove the .apk extension if present in the app name
                if self.app_file_path.lower().endswith(".apk"):
                    self.app_file_path = self.app_file_path[: -len(".apk")]
                
                self.download_link = f"https://apkaio.com/download-apk/{self.app_file_path}"
                
                if self.download_apk():
                    # Add the .apk extension if the downloaded file doesn't have it
                    downloaded_file_name = self.app_file_path
                    if not downloaded_file_name.lower().endswith(".apk"):
                        downloaded_file_name += ".apk"
                    
                    # Update the app_path attribute with the downloaded file name
                    self.app_file_path = downloaded_file_name
                else:
                    log.error("Unable to download the APK")
                    sys.exit(1)

                
        self.test_id = self.upload_app()
        self.test_progress()
        self.report_link()
     
    def download_apk(self):
        log.info(f"Downloading APK from: {self.download_link}")

        response = requests.get(self.download_link)
        if response.status_code == 200:
            download_url_match = re.search(r'<a href="(https?://[^"]+)"[^>]*>click here</a>', response.text)
            if download_url_match:
                download_url = download_url_match.group(1)
                apk_response = requests.get(download_url)
                if apk_response.status_code == 200:
                    # Append .apk extension to the file path
                    apk_path = f"{self.app_file_path}.apk"
                    with open(apk_path, "wb") as file:
                        file.write(apk_response.content)
                    self.app_file_path = apk_path  # Update the app_path attribute
                    log.success("Mobile app downloaded")
                    return True
                else:
                    log.error(f"Failed to download APK from {download_url}. Status code: {apk_response.status_code}")
            else:
                log.error("Download link not found in the HTML.")

        return False
        
        
        

    def upload_app(self):
        log.info("Uploading mobile app")
        url = self.baseurl + "upload"
        data = {
            "malware_check": "0",
            "hide_in_statistics": "0",
            "api_key": self.api_key
        }
        files = {
            "file": (self.app_file_path, open(self.app_file_path, "rb"))
        }
        response = requests.post(url, data=data, files=files)
        json_data = json.loads(response.content)
        test_id = json_data[1].get("id")
        log.success(f"App uploaded successfully with id: {test_id}")
        return test_id
        
        
    def test_progress(self):
        log.info("Scanning mobile app")
        url = self.baseurl + f"test_info/id/{self.test_id}"
        
        while True:
            response = requests.get(url)
            json_data = json.loads(response.content)
            test_status = json_data.get("status")
            
            if "finished" in test_status:
                break
            
            log.info(f"Scan status: {test_status} - waiting 15 seconds then trying again")
            time.sleep(15)
        
        log.success("Report is ready, generating the link now ...")
        time.sleep(0.5)


    def report_link(self):
        print('-' * 50)
        report_link = f"https://www.immuniweb.com/mobile/{self.app_file_path}/{self.test_id}"
        print('\033[92m[+]\033[0m' + f" \033[1mReport link:\033[0m \033[4m{report_link}\033[0m")
