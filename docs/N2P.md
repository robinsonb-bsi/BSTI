---
layout: default
title: Nessus2Plextrac
nav_order: 5
---

# Usage
If you prefer to use the tools from the commandline instead of within BSTI, the repo offerers standalone scripts for execution - the help for n2p-ng is below.

```bash
usage: n2p_ng.py [-h] [-u USERNAME] [-p PASSWORD] [-c CLIENT_ID] [-r REPORT_ID] [-s {internal,external,mobile,web,surveillance}] [-d DIRECTORY]
                 [-t {report}] [-ss SCREENSHOT_DIR] [-nc] [--create] [-v {0,1,2}] [-cf CLIENT_CONFIG]

Import Nessus scans files in Plextrac while regrouping findings

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        User's plextrac username
  -p PASSWORD, --password PASSWORD
                        User's plextrac password
  -c CLIENT_ID, --clientID CLIENT_ID
                        Client ID in plextrac
  -r REPORT_ID, --reportID REPORT_ID
                        Report ID in plextrac
  -s {internal,external,mobile,web,surveillance}, --scope {internal,external,mobile,web,surveillance}
                        Scope/Tag to add to the imported finding. Choose 'internal' for internal findings, 'external' for external findings, 'mobile'
                        for mobile findings, 'webapp' for web application-related findings, or 'surveillance' for surveillance-related findings.
  -d DIRECTORY, --directory DIRECTORY
                        Directory/Folder where to find the Nessus file[s]
  -t {report}, --targettedplextrac {report}
                        Targetted server [report]
  -ss SCREENSHOT_DIR, --screenshot_dir SCREENSHOT_DIR
                        Path to the directory containing the screenshots
  -nc, --noncore        Add non-core custom fields to findings
  --create              Prompt for client/report creation
  -v {0,1,2}, --verbosity {0,1,2}
                        increase output verbosity
  -cf CLIENT_CONFIG, --client_config CLIENT_CONFIG
                        Path to the TOML configuration file for client settings
```