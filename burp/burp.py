import requests
import time
import json
import os
import base64
import html
from scripts.logging_config import log
# TODO 
# add out of scope requests

class Burper:
    def __init__(self, api_url, api_key, burp_urls, usernames=None, passwords=None, reattach=False):
        self.api_key = api_key
        self.usernames = usernames
        self.passwords = passwords
        self.base_url = f"{api_url}/{api_key}"
        self.api_endpoint = '/v0.1/scan'
        self.api_issues_endpoint = '/v0.1/scan/{}'
        self.api_progress_endpoint = '/v0.1/scan/{}'
        self.headers = {
            'Content-Type': 'application/json',
        }
        self.target_urls = burp_urls
        self.scan_type = 'Crawl and Audit - Balanced'
        self.report_output = 'burp_scan_report.html'
        if reattach:
            log.info("Checking if scan can be attached")
            self.reattach()
        else:
            self.engine()
        

    def launch_scan(self, scan_type):
        application_logins = [{
            'type': 'UsernameAndPasswordLogin',
            'username': self.usernames,
            'password': self.passwords
        }]
        scan_configurations = [{
            'type': 'NamedConfiguration',
            'name': 'Crawl and Audit - Balanced'
        }]

        payload = {
            'urls': self.target_urls,
            'scan_configurations': scan_configurations
        }

        response = requests.post(self.base_url + self.api_endpoint, json=payload, headers=self.headers)
        try:
            if response.status_code == 201:
                scan_id = response.headers.get('Location').split('/')[-1]
                log.success(f'Scan launched successfully with ID: {scan_id}')
                
                # Create a dictionary with scan configurations and ID
                scan_data = {
                    'scan_configurations': scan_configurations,
                    'scan_id': scan_id,
                    'application_logins': application_logins,
                    'payload': payload,
                    'url': self.base_url + self.api_endpoint,
                    'targets': self.target_urls
                }
                
                # Save the scan data to a JSON file
                with open('scan_data.json', 'w') as json_file:
                    json.dump(scan_data, json_file)
                
                return scan_id
            elif response.status_code == 401:
                log.error('Authentication failed. Please check your API key.')
                return None
            else:
                print(response.content)
                log.error(f'Failed to launch scan. Status code: {response.status_code}')
                raise ValueError('Failed to launch scan')
        except Exception as e:
            log.error(e)


    def get_scan_progress(self, scan_id):
        progress_endpoint = self.api_progress_endpoint.format(scan_id)
        progress_response = requests.get(self.base_url + progress_endpoint, headers=self.headers)

        if progress_response.status_code == 200:
            progress_data = progress_response.json()
            return progress_data
        else:
            log.error('Failed to retrieve scan progress.')


    def get_scan_issues(self, scan_id):
        issues_endpoint = self.api_issues_endpoint.format(scan_id)
        issues_response = requests.get(self.base_url + issues_endpoint, headers=self.headers)

        if issues_response.status_code == 200:

            issues_data = json.loads(issues_response.text)
            return issues_data.get('issue_events')
        else:
            log.error('Failed to retrieve scan issues.')

    def generate_html_report(self, issues_data):
        html_report = '''
        <html>
        <head>
        <title>Scan Report</title>
        <style>
        body {
            background-color: #333;
            color: #fff;
            font-family: Arial, sans-serif;
        }
        .summary-table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }

        .summary-table th,
        .summary-table td {
            padding: 8px;
            text-align: center;
            border: 1px solid #ddd;
        }
        .summary-table th.severity,
        .summary-table td.severity {
            width: 120px;
        }

        .summary-table th {
            background-color: #444;
            font-weight: bold;
            text-align: center;
            padding: 10px;
            border: none;
            color: #fff;
        }

        .summary-table th:nth-child(1) {
            border-top-left-radius: 5px;
        }

        .summary-table th:last-child {
            border-top-right-radius: 5px;
        }
        
        .severity-high {
            background-color: #FF5A5A;
            color: #FFF;
        }

        .severity-medium {
            background-color: #FFAA00;
            color: #000;
        }

        .severity-low {
            color: #fff;
            background-color: #FFCC00; /* Darker yellow */
        }


        .severity-information {
            background-color: #7EB6FF;
            color: #000;
        }

        .confidence-certain {
            background-color: #91FF97;
            color: #000;
        }

        .confidence-firm {
            background-color: #FFFF6B;
            color: #000;
        }

        .confidence-tentative {
            color: #fff;
            background-color: #FFCC00; /* Darker yellow */
        }
        
        /* Add custom CSS for the table of contents */
        .toc-entry {
            
            margin-bottom: 10px;
        }
        
        .toc-entry a {
            color: #1E90FF; /* Dodger Blue */
            text-decoration: none;
        }

        
        .toc-arrow::before {
            content: "\\25B6";
            margin-right: 5px;
            display: inline-block;
            transform: rotate(0deg);
            transition: transform 0.3s;
        }
        
        .toc-entry:hover .toc-arrow::before {
            transform: rotate(90deg);
        }
        
        h1 {
            color: #fff;
            font-size: 24px;
        }
        
        h2 {
            color: #fff;
            font-size: 20px;
        }
        
        ul {
            list-style-type: none;
            padding: 0;
            margin: 0;
        }
        
        li {
            margin-bottom: 10px;
        }
        
        a {
            color: #fff;
            text-decoration: none;
        }
        
        .terminal {
            background-color: #000;
            color: #fff;
            padding: 10px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        
        .issue-item {
            margin-bottom: 20px;
            padding: 10px;
            background-color: #222;
            border-radius: 5px;
        }
        
        .issue-name {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .issue-property {
            margin-bottom: 5px;
        }
        
        .mini-header {
            font-size: 16px;
            font-weight: bold;
            margin-top: 10px;
            margin-bottom: 5px;
        }
        
        /* Add custom CSS for the table */
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th,
        .table td {
            padding: 8px;
            text-align: left;
            font-weight: bold;
            border-bottom: 1px solid #555;
        }
        
        /* Style Severity and Confidence columns */
        .table th.severity,
        .table td.severity {
            width: 120px;
        }
        
        .table th.confidence,
        .table td.confidence {
            width: 120px;
        }
        
        /* Add custom CSS for sections */
        .section {
            margin-top: 20px;
            margin-bottom: 20px;
            padding: 10px;
            background-color: #333;
            border-radius: 5px;
        }
        
        .section-header {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        /* Customize evidence styles for readability */
        .evidence {
            background-color: #111;
            color: #ccc;
            padding: 10px;
            border-radius: 5px;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        /* Add custom CSS for severity colors */
        .severity-high {
            color: #fff;
            background-color: #FF4136; /* Red */
        }
        
        .severity-medium {
            color: #fff;
            background-color: #FF851B; /* Orange */
        }
        
        .severity-low {
            color: #fff;
            background-color: #FFDC00; /* Yellow */
        }
        
        .severity-info {
            color: #fff;
            background-color: #0074D9; /* Blue */
        }
        
        .severity-undefined {
            color: #fff;
            background-color: #AAAAAA; /* Gray */
        }
        
        .severity-false_positive {
            color: #fff;
            background-color: #2ECC40; /* Green */
        }
        
        /* Add custom CSS for confidence colors */
        .confidence-certain {
            color: #fff;
            background-color: #FF4136; /* Red */
        }
        
        .confidence-firm {
            color: #fff;
            background-color: #FF851B; /* Orange */
        }
        
        .confidence-tentative {
            color: #fff;
            background-color: #FFDC00; /* Yellow */
        }
        
        .confidence-undefined {
            color: #fff;
            background-color: #AAAAAA; /* Gray */
        }
        .url-wrapper {
            display: inline-block;
            background-color: #000;
            padding: 5px 10px;
            border-radius: 5px;
        }

        .url-text {
            color: #fff;
            font-weight: bold;
        }

        
        </style>
        </head>
        <body>
        <h1>Scan Report</h1>
        <div class="summary-table">
            <h2>Summary</h2>
        </div>
        '''
        
        html_report += '<hr>\n'  
        html_report += "<h3>Scope Targets</h3>\n"
        html_report += '<table class="table">\n'
        html_report += '<thead>\n'
        html_report += '<tr>\n'
        html_report += '<th>URLs</th>\n'
        html_report += '</tr>\n'
        html_report += '</thead>\n'
        html_report += '<tbody>\n'
        for url in self.target_urls:
            html_report += '<tr>\n'
            html_report += '<td><div class="url-wrapper"><span class="url-text">' + url + '</span></div></td>\n'
            html_report += '</tr>\n'
        html_report += '</tbody>\n'
        html_report += '</table>\n'
        html_report += '<hr>\n'

        if not self.usernames and not self.passwords:
            self.usernames = 'none'
            self.passwords = 'none'
        html_report += '<hr>\n'  
        html_report += "<h3>Credentials Used</h3>\n"
        html_report += '<table class="table">\n'
        html_report += '<thead>\n'
        html_report += '<tr>\n'
        html_report += '<th>Creds</th>\n'
        html_report += '</tr>\n'
        html_report += '</thead>\n'
        html_report += '<tbody>\n'

        # Iterate over the usernames and passwords simultaneously
        for username, password in zip(self.usernames, self.passwords):
            html_report += '<tr>\n'
            html_report += '<td><div class="url-wrapper"><span class="url-text">' + f"{username}:{password}" + '</span></div></td>\n'
            html_report += '</tr>\n'

        html_report += '</tbody>\n'
        html_report += '</table>\n'
        html_report += '<hr>\n'
        
        # Define all possible severity levels and confidence values
        all_severities = ['high', 'medium', 'low', 'info']
        all_confidences = ['certain', 'firm', 'tentative']
        
        # Count the occurrences of each severity and confidence level
        severity_confidence_counts = {}
        
        if issues_data:
            for event in issues_data:
                issue = event.get('issue')
                severity = issue.get('severity')
                confidence = issue.get('confidence')
                key = (severity, confidence)
                severity_confidence_counts[key] = severity_confidence_counts.get(key, 0) + 1

        
        html_report += "<h3>Issue Count</h3>\n"
        html_report += '<table class="summary-table">\n'
        html_report += '<tr>\n'
        html_report += '<th>Severity</th>\n'
        
        for confidence in all_confidences:
            html_report += f'<th class="confidence">{confidence}</th>\n'

        html_report += '<th>Total</th>\n'
        html_report += '</tr>\n'

        for severity in all_severities:
            html_report += '<tr>\n'
            html_report += f'<td class="severity-{severity.lower()}"><strong>{severity}</strong></td>\n'
            row_total = 0
            for confidence in all_confidences:
                key = (severity, confidence)
                count = severity_confidence_counts.get(key, 0)
                html_report += f'<td class="confidence-{confidence.lower()}"><strong>{count}</strong></td>\n'
                row_total += count
            html_report += f'<td><strong>{row_total}</strong></td>\n'
            html_report += '</tr>\n'

        html_report += '</table>\n'
        html_report += '</div>\n'
        html_report += '<hr>\n'  

        html_report += '<h2>Table of Contents</h2>\n'
        html_report += '<ul>\n'
        
        if issues_data:
            for event in issues_data:
                issue = event.get('issue')
                issue_name = issue.get('name')
                url = issue.get('origin')
                html_report += f'<li class="toc-entry"><a href="#{issue_name.lower().replace(" ", "_")}"><span class="toc-arrow"></span>{issue_name}</a></li>\n'

            html_report += '</ul>\n'

            for event in issues_data:
                issue = event.get('issue')
                issue_name = issue.get('name')
                severity = issue.get('severity')
                confidence = issue.get('confidence')
                description = issue.get('description')
                remediation = issue.get('remediation')
                issue_background = issue.get('issue_background')
                remediation_background = issue.get('remediation_background')
                caption = issue.get('caption')
                evidence = issue.get('evidence')


                # Header
                html_report += f'<div class="issue-item" id="{issue_name.lower().replace(" ", "_")}">\n'
                html_report += f'<div class="issue-name">{issue_name}</div>\n'
                
                
                # Display the affected url
                html_report += f'<div class="section">\n'
                html_report += '<div class="section-header">Base Tested URL:</div>\n'
                html_report += f'<div class="issue-property">{url}</div>\n'
                html_report += '</div>\n'
                        
                # Create a table for Severity and Confidence
                html_report += '<table class="table">\n'
                html_report += '<tr>\n'
                html_report += '<th class="severity">Severity</th>\n'
                html_report += '<th class="confidence">Confidence</th>\n'
                html_report += '</tr>\n'
                html_report += '<tr>\n'
                html_report += f'<td class="severity severity-{severity.lower()}"><span>{severity}</span></td>\n'
                html_report += f'<td class="confidence confidence-{confidence.lower()}"><span>{confidence}</span></td>\n'
                html_report += '</tr>\n'
                html_report += '</table>\n'
                
                
                # Add a section for Description
                if description:
                    html_report += '<div class="section">\n'
                    html_report += '<div class="section-header">Description:</div>\n'
                    html_report += f'<div class="issue-property">{description}</div>\n'
                    html_report += '</div>\n'
                
                # Add a section for Remediation
                if remediation:
                    html_report += '<div class="section">\n'
                    html_report += '<div class="section-header">Remediation:</div>\n'
                    html_report += f'<div class="issue-property">{remediation}</div>\n'
                    html_report += '</div>\n'
                
                # Add a section for Issue Background
                if issue_background:
                    html_report += '<div class="section">\n'
                    html_report += '<div class="section-header">Issue Background:</div>\n'
                    html_report += f'<div class="issue-property">{issue_background}</div>\n'
                    html_report += '</div>\n'
                
                # Add a section for Remediation Background
                if remediation_background:
                    html_report += '<div class="section">\n'
                    html_report += '<div class="section-header">Remediation Background:</div>\n'
                    html_report += f'<div class="issue-property">{remediation_background}</div>\n'
                    html_report += '</div>\n'
                
                # Add a section for Caption
                if caption:
                    html_report += '<div class="section">\n'
                    html_report += '<div class="section-header">Caption:</div>\n'
                    html_report += f'<div class="issue-property">{caption}</div>\n'
                    html_report += '</div>\n'
                
                # Add a section for Evidence
                if evidence:
                    html_report += '<div class="section">\n'
                    html_report += '<div class="section-header">Evidence:</div>\n'
                    for i, item in enumerate(evidence, 1):
                        if 'request_response' in item:
                            request_response = item['request_response']
                            request_url = request_response.get('url')
                            request_data = request_response.get('request')
                            response_data = request_response.get('response')
                            if request_data:
                                if isinstance(request_data, list):
                                    request_data = [base64.b64decode(d['data']).decode('utf-8') if 'data' in d else '' for d in request_data]
                                    request_data = '\n'.join(request_data)
                                html_report += f'<div class="issue-property"><span class="mini-header">Request {i}:</span></div>\n'
                                html_report += '<div class="terminal">\n'
                                html_report += f'{html.escape(request_data)}\n'  # Escape HTML entities
                                html_report += '</div>\n' 
                            if response_data:
                                if isinstance(response_data, list):
                                    response_data = [base64.b64decode(d['data']).decode('utf-8') if 'data' in d else '' for d in response_data]
                                    response_data = '\n'.join(response_data)
                                html_report += f'<div class="issue-property"><span class="mini-header">Response {i}:</span></div>\n'
                                html_report += '<div class="terminal">\n'
                                html_report += f'{html.escape(response_data)}\n'  # Escape HTML entities
                                html_report += '</div>\n' 
                    html_report += '</div>\n' 

                html_report += '</div>\n'
                html_report += '<hr>\n'  # Add horizontal line after each issue

        else:
            html_report += '<p>No issues found.</p>\n'

        html_report += '</body>\n</html>'

        
        report_dir = 'reports'

        # Create the report directory if it doesn't exist
        os.makedirs(report_dir, exist_ok=True)

        # Specify the output file path
        output_path = os.path.join(report_dir, self.report_output)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_report)

        log.success(f'Report generated successfully as {output_path}')
        return True

    def engine(self):
        log.info('Scanning...')
        self.scan_id = self.launch_scan(self.scan_type)
        while True:
            # Get the scan progress
            progress_data = self.get_scan_progress(self.scan_id)
            if progress_data:
                status = progress_data.get('scan_status')
                if status == 'succeeded':
                    # Get the scan issues
                    log.success("Scan finished")
                    issues_data = self.get_scan_issues(self.scan_id)
                    # Generate the HTML report
                    if self.generate_html_report(issues_data):
                        break
                elif status == 'failed':
                    log.error('Scan failed.')
                    break
                elif status == 'paused':
                    log.warning('Unable to seed urls or scan was manually paused.')
                    break
            else:
                break
            time.sleep(10)

            
    def reattach(self):
        try:
            log.info('Reattaching...')
            with open('scan_data.json', 'r') as json_file:
                scan_data = json.load(json_file)
            scan_configurations = scan_data['scan_configurations']
            scan_id = scan_data['scan_id']
            self.target_urls = scan_data['targets']
            log.success("Scan reattached")
            while True:
                progress_data = self.get_scan_progress(scan_id)
                if progress_data:
                    status = progress_data.get('scan_status')
                    if status == 'succeeded':
                        # Get the scan issues
                        log.success("Scan finished")
                        issues_data = self.get_scan_issues(scan_id)
                        # Generate the HTML report
                        if self.generate_html_report(issues_data):
                            log.info("Report successfully created, deleting statefile...")
                            os.remove('scan_data.json')
                            log.success("Statefile removed")
                            break
                    elif status == 'failed':
                        log.error('Scan failed.')
                        break
                    elif status == 'paused':
                        log.warning('Unable to seed urls or scan was manually paused.')
                        break
                time.sleep(5)
        except FileNotFoundError:
            log.error('No scan data found. Please launch a scan first.')
        except Exception as e:
            log.error(e)