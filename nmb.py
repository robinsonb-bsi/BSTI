# Version of NMB adapted to fit bsti requirements 
# Author: Connor Fancy
# Version: 1.0
import argparse
import sys
import signal
import os
import pretty_errors
from scripts.nessus import Nessus
from scripts.creator import GenConfig
from mobsf.mobsf import Mobber
from scripts.lackey import Lackey
from burp.burp import Burper
from glob import glob
from dotenv import load_dotenv
from immuniweb.immuni import Immuniweb
from scripts.logging_config import log
load_dotenv()

# ================== Utility Functions ==================

class CredentialsCache:
    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password

    def get_creds(self):
        return self.username, self.password


def select_file(file_type):
    files = glob(f"*.{file_type}")
    
    # Filter out 'requirements.txt'
    files = [f for f in files if f != 'requirements.txt']

    if not files:
        log.error(f"No {file_type} files found in the current directory.")
        sys.exit()
    elif len(files) == 1:
        return files[0]
    else:
        log.info(f"Multiple {file_type} files found in the current directory.")
        for idx, file in enumerate(files, 1):
            print(f"{idx}. {file}")
        while True:
            try:
                choice = int(input(f"Enter the number of the {file_type} file: "))
                if 1 <= choice <= len(files):
                    return files[choice - 1]
            except ValueError:
                pass
            print("Invalid choice. Please enter a valid number.")


def find_policy_file(project_scope):
    policies = {
        'core': "Default Good Model Nessus Vulnerability Policy.nessus",
        'nc': "Custom_Nessus_Policy-Pn_pAll_AllSSLTLS-Web-NoLocalCheck-NoDOS.nessus"
    }
    
    # If project_scope is 'custom', prompt the user for the path
    if project_scope == 'custom':
        custom_path = input("Please enter the path to your custom policy file: ").strip()
        return os.path.normpath(custom_path)
    
    policy_dir = os.path.join(os.getcwd(), "Nessus-policy")
    return os.path.normpath(os.path.join(policy_dir, policies.get(project_scope, "")))


def read_burp_targets(targets_file_path):
    with open(targets_file_path, 'r') as targets_file:
        return [url.strip() for url in targets_file.readlines() if url.strip()]

def read_credentials(username_file_path, password_file_path):
    try:
        if not username_file_path:
            return
        with open(username_file_path, 'r') as username_file, open(password_file_path, 'r') as password_file:
            usernames = [u.strip() for u in username_file.read().split('\n') if u.strip()]
            passwords = [p.strip() for p in password_file.read().split('\n') if p.strip()]
            return usernames, passwords
    except Exception as e:
        log.warning(f"Burp scan will be executed without credentials due to: {str(e)}")
        return None, None

def determine_execution_mode(args):
    return bool(args.local)

def signal_handler(signal, frame):
    print()
    log.warning("Ctrl+C detected. Exiting...")
    sys.exit(0)


# ================== Mode Handlers ==================

def handle_mode(args, mode, required_args, handler_info):
    if getattr(args, 'local', False) and "drone" in required_args:
        required_args.remove("drone")
    
    missing_args = [arg for arg in required_args if not getattr(args, arg)]
    if missing_args:
        log.error(f"Missing required arguments for {mode} mode: {', '.join(missing_args)}")
        sys.exit(1)
    
    # Handle modes that use the old structure
    if 'handler_class' in handler_info:
        handler_classes_with_args_providers = [(handler_info['handler_class'], handler_info['handler_args_providers'])]
    else:
        handler_classes_with_args_providers = handler_info['handler_classes_with_args_providers']
    
    try:
        for handler_class, handler_args_providers in handler_classes_with_args_providers:
            handler_args = []
            handler_kwargs = {}
            for provider in handler_args_providers:
                result = provider(args)
                if isinstance(result, tuple):
                    handler_args.extend(result)
                elif isinstance(result, dict):
                    handler_kwargs.update(result)
                else:
                    handler_args.append(result)
            
            # Call the handler class with both positional and keyword arguments
            handler_class(*handler_args, **handler_kwargs)
    except Exception as e:
        log.error(f"An error occurred during {mode} execution: {str(e)}")



# === Main Execution ===
def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_arguments()
    creds_cache = CredentialsCache(username=args.username, password=args.password)

    mode_config = {
        "mobsf": {
            "required_args": ["mobsf_url", "mobsf_scan_type", "mobsf_app_name"],
            "handler_class": Mobber,
            "handler_args_providers": [lambda args: args.mobsf_url, 
                                       lambda args: args.mobsf_scan_type, 
                                       lambda args: args.mobsf_app_name]
        },
        "web": {
            "required_args": ["burp_targets", "burp_url"],
            "handler_class": Burper,
            "handler_args_providers": [lambda args: args.burp_url or "http://127.0.0.1:1337", 
                                       lambda _: os.getenv("BURP_API_KEY"),
                                       lambda args: read_burp_targets(args.burp_targets),
                                       lambda args: read_credentials(args.burp_target_user_file, args.burp_target_pass_file),
                                       lambda args: args.burp_reattach or False]
                                       
        },
        "immuniweb": {
            "required_args": ["immuni_scan_type", "immuni_app_name"],
            "handler_class": Immuniweb,
            "handler_args_providers": [lambda _: os.getenv("IMMUNIWEB_API_KEY"), 
                                       lambda args: args.immuni_scan_type, 
                                       lambda args: args.immuni_app_name]
        },
        "deploy": {
            "required_args": ["client", "drone", "project_type"],
            "handler_classes_with_args_providers": [
                (Nessus, [
                    lambda args: args.drone, 
                    lambda _: creds_cache.get_creds(),
                    lambda _: args.mode,
                    lambda args: args.client,
                    lambda args: find_policy_file(args.project_type), 
                    lambda _: select_file('txt'),
                    lambda args: args.exclude_file, 
                    lambda args: args.discovery
                ]),
                (Lackey, [
                    lambda _: select_file('csv'),
                    lambda _: None,
                    lambda args: determine_execution_mode(args),
                    lambda _: creds_cache.get_creds() if not getattr(args, 'local', False) else (None, None),
                    lambda args: args.drone, 
                    lambda args: args.enable_guessing,
                    lambda args: args.run_eyewitness
                ])
            ]
        },
        "internal": {
            "required_args": ["drone"],
            "handler_class": Lackey,
            "handler_args_providers": [lambda _: select_file('csv'),
                                       lambda _: None,
                                       lambda args: determine_execution_mode(args),
                                       lambda _: creds_cache.get_creds() if not getattr(args, 'local', False) else (None, None),
                                       lambda args: args.drone, 
                                       lambda args: args.enable_guessing,
                                       lambda args: args.run_eyewitness]
        },
        "external": {
            "required_args": ["drone"],
            "handler_class": Lackey,
            "handler_args_providers": [lambda _: select_file('csv'),
                                       lambda _: True,
                                       lambda args: determine_execution_mode(args),
                                       lambda _: creds_cache.get_creds() if not getattr(args, 'local', False) else (None, None),
                                       lambda args: args.drone, 
                                       lambda args: args.enable_guessing,
                                       lambda args: args.run_eyewitness]
        },
        "create": {
            "required_args": ["client", "drone", "project_type"],
            "handler_class": Nessus,
            "handler_args_providers": [lambda args: args.drone, 
                                       lambda _: creds_cache.get_creds(),
                                       lambda _: args.mode,
                                       lambda args: args.client,
                                       lambda args: find_policy_file(args.project_type), 
                                       lambda _: select_file('txt'),
                                       lambda args: args.exclude_file, 
                                       lambda args: args.discovery]
        },
        "launch": {
            "required_args": ["client", "drone"],
            "handler_class": Nessus,
            "handler_args_providers": [lambda args: args.drone, 
                                       lambda _: creds_cache.get_creds(),
                                       lambda _: args.mode,
                                       lambda args: args.client]
        },
        "pause": {
            "required_args": ["client", "drone"],
            "handler_class": Nessus,
            "handler_args_providers": [lambda args: args.drone, 
                                       lambda _: creds_cache.get_creds(),
                                       lambda _: args.mode,
                                       lambda args: args.client]
        },
        "resume": {
            "required_args": ["client", "drone"],
            "handler_class": Nessus,
            "handler_args_providers": [lambda args: args.drone, 
                                       lambda _: creds_cache.get_creds(),
                                       lambda _: args.mode,
                                       lambda args: args.client]
        },
        "monitor": {
            "required_args": ["client", "drone"],
            "handler_class": Nessus,
            "handler_args_providers": [lambda args: args.drone, 
                                       lambda _: creds_cache.get_creds(),
                                       lambda _: args.mode,
                                       lambda args: args.client]
        },

        "regen": {
            "required_args": [],
            "handler_class": GenConfig,
            "handler_args_providers": [lambda _: {"regen": True}]
        },


        "export": {
            "required_args": ["client", "drone"],
            "handler_class": Nessus,
            "handler_args_providers": [lambda args: args.drone, 
                                       lambda _: creds_cache.get_creds(),
                                       lambda _: args.mode,
                                       lambda args: args.client]
        }
    }

    mode_info = mode_config.get(args.mode)
    if not mode_info:
        log.error("Invalid mode selected")
        print("Options are: [mobsf, web, deploy, create, launch, pause, resume, monitor, export, internal, external, immuniweb]")
        sys.exit(1)

    handle_mode(args, args.mode, mode_config[args.mode]["required_args"], mode_config[args.mode])



# === Argument Parsing ===
def parse_arguments():
    signal.signal(signal.SIGINT, signal_handler)
    parser = argparse.ArgumentParser(
        usage = "nmb.py [OPTIONS]",
        formatter_class = argparse.RawTextHelpFormatter,
        epilog = "Examples:\n" \
                 "nmb.py -d storm -c myclient -m deploy -s core\n" \
                 "nmb.py -d localhost -c myclient -m create\n" \
                 "nmb.py -d 10.88.88.101 -c myclient -m pause\n" \
                 "nmb.py -d strange -c myclient -m resume -o /home/drone/Downloads\n" \
                 "nmb.py -m internal -d ironman \n" \
                 "nmb.py -m internal --local\n" \
                 "nmb.py -m external -d pendrone\n" \
                 "nmb.py -m web -tf targets.txt -bu http://192.168.2.1:1337\n" \
                 "nmb.py -m mobsf -an com.example.apk -st apk -mu <mobsfURL>\n" \
                 "nmb.py -m immuniweb --force -is ipa -ia com.example.ipa\n" \
                 "nmb.py -m immuniweb -is apk -ia com.example.apk"
    )
    parser.add_argument("-m", "--mode", required=False, choices=["deploy","create","launch","pause","resume","monitor","export", "web", "mobsf", "external", "internal", "immuniweb", "regen"], help="" \
        "choose mode to run Nessus:\n" \
        "deploy: update settings, upload policy file, upload targets file, launch scan, monitor scan, export results, analyze results\n" \
        "create: update settings, upload policy file, upload targets files\n" \
        "launch: launch scan, export results, analyze results\n" \
        "pause: pause scan\n" \
        "resume: resume scan, export results, analyze results\n" \
        "monitor: monitor scan\n" \
        "export: export scan results, analyze results\n" \
        "mobsf: Download apk, static scan, export pdf report \n" \
        "web: Start burpscan, monitor scan, export html, analyze results, take screenshots\n" \
        "external: perform nmap scans, manual finding verification, generate external report, take screenshots\n" \
        "internal: perform nmap scans, manual finding verification, generate internal report, take screenshots\n" \
        "immuniweb: Download apk, static scan, generate report link\n" \
        "regen: Regenerates 'NMB_config.json'"
    )

    # UTIL
    parser.add_argument("-u", "--username", required=False, help="Username for the drone")
    parser.add_argument("-p", "--password", required=False, help="Password for the drone")

    # WEB
    parser.add_argument("-uf", "--burp-user-file", dest="burp_target_user_file", required=False, help="Username file of targetsite")
    parser.add_argument("-pf", "--burp-pass-file", dest="burp_target_pass_file", required=False, help="Password file of targetsite")
    parser.add_argument("-tf", "--targets", dest="burp_targets", required=False, help="burp web targets file")
    parser.add_argument("-bu", "--burp-url", dest="burp_url", required=False, help="local burp API url")
    parser.add_argument("--reattach", dest="burp_reattach", required=False, action="store_const", const=True, help="reattach to burp scan if script dies")
    # MOBSF
    parser.add_argument("-mu", "--mobsf-url", dest="mobsf_url", required=False, help="Url of your mobsf instance with the port (http://localhost:8000)")
    parser.add_argument("-st", "--scan-type", dest="mobsf_scan_type", required=False, choices=["apk", "ipa"], help="Scan type <apk or ipa>")
    parser.add_argument("-an", "--app-name", dest="mobsf_app_name", required=False, help="com name of the app for automatic download, or path to mobile app")
    
    # IMMUNIWEB
    parser.add_argument("-is", dest="immuni_scan_type", required=False, choices=["apk", "ipa"], help="Scan type <apk or ipa>")
    parser.add_argument("-ia", dest="immuni_app_name", required=False, help="com name of the app for automatic download, or path to mobile app")
    parser.add_argument("--force", dest="force_no_api", required=False, action="store_const", const=True, help="run immuniweb without an API key (Up to two scans per day)")
    
    # INTERNAL/EXTERNAL
    parser.add_argument("-d", "--drone", required=False, help="drone name or IP")
    parser.add_argument("-c", "--client-name", dest="client", required=False, help="client name or project name (used to name the scan and output files)")
    parser.add_argument("-s", "--scope", dest="project_type", required=False, choices=["core", "nc", "custom"], help="Specify if core, custom or non-core policy file")
    parser.add_argument("-e", "--exclude-file", dest="exclude_file", required=False, help="exclude targets file", type=argparse.FileType('r'))
    parser.add_argument("-ex", "--external", dest="external", required=False, action="store_const", const=True, help="Enable external mode")
    parser.add_argument("-l", "--local", dest="local", required=False, action="store_const", const=True, help="run manual checks on your local machine instead of over ssh")
    parser.add_argument("--discovery", dest="discovery", required=False, action="store_const", const=True, help="Enable discovery scan prior to running nessus.")
    parser.add_argument("--guess", dest="enable_guessing", required=False, action="store_const", const=True, help="Enable guessing mode for lackey")
    parser.add_argument("--eyewitness", dest="run_eyewitness", required=False, action="store_const", const=True, help="Enable eyewitness mode for lackey")

    args = parser.parse_args()
    return args

    
if __name__ == '__main__':
    main()
