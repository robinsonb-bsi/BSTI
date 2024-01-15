import csv
import json
import re
import os
from collections import defaultdict

class Interpreter:
    UNWANTED_STRINGS = {".org", ".io", ".js", ".com", ",", "\"", "\'", ":*", ".png", "css", ".net", ".ico"}
    SERVICE_DETECT_KEYWORDS = {'Service Detect', 'SQL Server', 'Server Detect'}
    FQDN_PATTERN = re.compile(r'(?:FQDN\s+:\s+|Common name:|CN[:=])(?![^|/\n]*\*)([^|/\n]+)')
    HTTP_PATTERN = re.compile(r'https?://\S+')

    def __init__(self, csv_file, client_dir):
        self.csv_file = csv_file
        self.client_dir = client_dir
        self.output_file = 'Interpreter_output.html'
        self.output_path = os.path.join(self.client_dir, self.output_file)
        self.mindmap_data = self.read_mindmap_json()
        self.generate_html_output()

    @staticmethod
    def read_mindmap_json():
        with open("mindmap.json", 'r', encoding='utf-8') as file:
            return json.load(file)

    def read_csv_and_collect_info(self):
        nessus_data = defaultdict(lambda: defaultdict(list))
        os_info = {}
        basic_host_info = defaultdict(list)
        dns_hostnames = {}
        vulnerability_info = defaultdict(list)
        http_info = defaultdict(list)

        with open(self.csv_file, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                self.collect_nessus_data(row, nessus_data)
                self.collect_os_info(row, os_info)
                self.collect_basic_host_info(row, basic_host_info)
                self.collect_dns_hostnames(row, dns_hostnames)
                self.collect_vulnerability_info(row, vulnerability_info)
                self.collect_http_info(row, http_info)

        # Filter HTTP info
        self.filter_http_info(http_info)

        return nessus_data, os_info, basic_host_info, dns_hostnames, vulnerability_info, http_info

    def collect_nessus_data(self, row, nessus_data):
        name = row['Name']
        plugin_output = row['Plugin Output']
        host = row['Host']
        port = row['Port']
        if any(keyword in name for keyword in self.SERVICE_DETECT_KEYWORDS):
            output_to_use = name if not plugin_output or len(plugin_output) > 110 else plugin_output
            if port.isdigit():
                nessus_data[output_to_use][int(port)].append(host)

    def collect_os_info(self, row, os_info):
        if row['Name'] == 'OS Identification':
            plugin_output = row['Plugin Output']
            os_description = plugin_output.split('\n')[1] if '\n' in plugin_output else 'Unknown OS'
            os_info[row['Host']] = os_description.replace('Remote operating system :', '').strip()

    def collect_basic_host_info(self, row, basic_host_info):
        if 'Nessus SYN scanner' in row['Name'] and row['Port'].isdigit():
            basic_host_info[row['Host']].append(int(row['Port']))

    def collect_dns_hostnames(self, row, dns_hostnames):
        plugin_output = row['Plugin Output']
        matches = self.FQDN_PATTERN.findall(plugin_output)
        for match in matches:
            if '.' in match and not match.startswith("ip-"):
                dns_hostnames[row['Host']] = match
                break

    def collect_vulnerability_info(self, row, vulnerability_info):
        if row['Risk'] != 'None':
            cve = row.get('CVE', 'N/A')
            cvss = row.get('CVSS v2.0 Base Score', 'N/A')
            name = row.get('Name', 'N/A')
            description = row.get('Description', 'N/A')
            ports = row.get('Port', 'N/A')
            risk = row.get('Risk', 'N/A')
            vulnerability_info[name].append((description, cve, cvss, row['Host'], ports, risk))

    def collect_http_info(self, row, http_info):
        plugin_output = row['Plugin Output']
        if 'http://' in plugin_output or 'https://' in plugin_output:
            http_info[row['Host']].extend(self.HTTP_PATTERN.findall(plugin_output))

    @classmethod
    def filter_http_info(cls, http_info):
        for host, urls in list(http_info.items()):
            filtered_urls = {url for url in urls if not any(unwanted in url for unwanted in cls.UNWANTED_STRINGS)}
            http_info[host] = list(filtered_urls)

    def generate_bash_script(self, http_info):
        bash_script = """
        #!/bin/bash

        # List of URLs to check
        declare -a URL_LIST=({urls})

        # Loop through each URL
        for url in "${{URL_LIST[@]}}"; do
            # Get HTTP status code using curl
            STATUS_CODE=$(curl -o /dev/null -s -w "%{{http_code}}" "$url")

            # Check if the status code is 200
            if [ "$STATUS_CODE" == "200" ]; then
                echo "$url returned 200 OK. Taking screenshot..."
                
                # Use EyeWitness.py to grab a screenshot
                ./EyeWitness.py -f <(echo "$url") --web

            else
                echo "$url returned $STATUS_CODE"
            fi
        done
        """

        urls = ' '.join(f'"{url}"' for hosts in http_info.values() for url in hosts)
        bash_script = bash_script.replace("{urls}", urls)
        return bash_script


    def generate_html_output(self):
        # this is messy but im lazy at the moment 
        nessus_data, os_info, basic_host_info, dns_hostnames, vulnerability_info, http_info = self.read_csv_and_collect_info()
        mindmap_data = self.read_mindmap_json()

        # Initial HTML content
        html_content = """
        <html>
        <head>
            <title>Interpreter (v1)</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css">
            <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
            <style>
                /* Dark mode styles */
                body {
                    background-color: #121212;
                    color: #ffffff;
                    font-family: Arial, sans-serif;
                    font-size: 16px;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .collapsible, .vulnerability {
                    background-color: #333;
                    color: #fff;
                    cursor: pointer;
                    padding: 10px;
                    width: 100%;
                    border: none;
                    outline: none;
                    font-size: 18px;
                    text-align: left;
                    margin-bottom: 5px;
                }
                .collapsible .icons, .vulnerability .icons {
                    float: right;
                }
                .content, .content-service, .content-vulnerability {
                    padding: 10px;
                    display: none;
                    overflow: hidden;
                    background-color: #444;
                    text-align: left;
                }
                .collapsible-service, .collapsible-service, .collapsible-vulnerability {
                    background-color: #555;
                    color: #fff;
                    cursor: pointer;
                    padding: 10px;
                    width: 100%;
                    border: none;
                    outline: none;
                    font-size: 16px;
                    text-align: left;
                    margin-bottom: 5px;
                }
                .content-service, .content-service, .content-vulnerability {
                    padding: 0 10px;
                    display: none;
                    overflow: hidden;
                    background-color: #666;
                    text-align: left;
                }
                .ip-address, .ip-address, .ip-address {
                    padding-left: 20px;
                    list-style-type: square;
                }
                textarea {
                    width: 100%;
                    min-height: 100px; /* Increase the height here */
                }
                .hidden {
                    display: none;
                }
                .links {
                    margin-top: 10px;
                }
                .links a {
                    color: #0078d4;
                    text-decoration: underline;
                    margin-right: 10px;
                }
                .host-info-item {
                    display: flex; /* Use flexbox for horizontal layout */
                    justify-content: space-between; /* Space items evenly */
                    align-items: center; /* Center items vertically */
                }
                .host-entry {
                    display: flex;
                    justify-content: space-between;
                    padding: 0px 0;
                }

                .host-entry .host-ip, .host-entry .host-os, .host-entry .host-dns {
                    padding: 0 10px;
                }

                .host-entry .host-ip {
                    text-align: left;
                    flex-basis: 20%;  /* example: allocate 20% width to IP */
                }

                .host-entry .host-os {
                    text-align: left;
                    flex-basis: 40%;  /* example: allocate 40% width to OS */
                }

                .host-entry .host-dns {
                    text-align: right;
                    flex-basis: 40%;  /* example: allocate 40% width to DNS */
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Interpreter</h1>
                <button id='expandAll' onclick='expandAllSections()'>Expand All</button>
                <button id='collapseAll' onclick='collapseAllSections()'>Collapse All</button>
        """

        # Include Basic Host Information with DNS hostnames
        html_content += "<div class='collapsible-container'>"
        html_content += "<div class='collapsible' onclick='toggleContent(this)'><span class='service'><strong>Host Info</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
        html_content += "<div class='content'>"

        # Sorting the basic host information based on OS description
        sorted_basic_host_info = sorted(basic_host_info.items(), key=lambda x: os_info.get(x[0], ''))
        for host, ports in sorted_basic_host_info:
            os_description = os_info.get(host, 'Unknown OS')
            # Include DNS hostname, if available
            dns_hostname = dns_hostnames.get(host, '')

            html_content += "<div class='collapsible-container-service'>"
            html_content += "<div class='collapsible-service' onclick='toggleContentService(this)'>"
            html_content += "<div class='host-entry'>"
            html_content += f"<span class='host-ip'>{host}</span>"
            html_content += f"<span class='host-os'>{os_description}</span>"
            html_content += f"<span class='host-dns'>{dns_hostname}</span>"
            html_content += "</div>"
            html_content += "<span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
            html_content += "<div class='content-service'>"
            html_content += f"<p><strong class='service'>Ports: {', '.join(map(str, ports))}</strong></p>"

            
            # Add links and notes from mindmap for each host
            for port in ports:
                port_data = mindmap_data.get(str(port))
                if port_data:
                    link = port_data.get('Link')
                    notes = port_data.get('Notes')
                    if link:
                        # Split multiple links by newline character and display them separately
                        links = link.split('\n')
                        for link_item in links:
                            # Display "Port X:" before each hyperlink
                            html_content += f"<p><strong>Port {port}:</strong> <a href='{link_item.strip()}' target='_blank'>{link_item.strip()}</a></p>"
                    if notes:
                        html_content += f"<p><strong>Notes:</strong> {notes}</p>"

            html_content += "</div></div>"

        html_content += "</div></div>"

        # Sort the nessus_data based on the character count of Plugin Output
        nessus_data_sorted = sorted(nessus_data.items(), key=lambda item: len(item[0]))

        # List of keywords or phrases to filter out
        filter_out_keywords = ["SSL certificate", "Server Status", "banner", "https://", "ping"]

        # Include Service Info
        html_content += "<div class='collapsible-container'>"
        html_content += "<div class='collapsible' onclick='toggleContent(this)'><span class='service'><strong>Service Info</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
        html_content += "<div class='content'>"
        for plugin_output, ports_data in nessus_data_sorted:
            # Check if the plugin_output contains any of the keywords to filter out
            if any(keyword in plugin_output for keyword in filter_out_keywords):
                continue  # Skip this entry

            html_content += f"<div class='collapsible-container-service'><div class='collapsible-service' onclick='toggleContentService(this)'><span class='service'><strong>Service: {plugin_output}</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
            html_content += "<div class='content-service'>"
            for port, hosts in ports_data.items():
                html_content += "<p><strong>Port:</strong> {}\n".format(port)
                html_content += "<textarea readonly='' rows='4' cols='50'>\n"
                html_content += "\n".join(hosts)
                html_content += "</textarea></p>"

                # Include mindmap data for this port, if available
                mindmap_port_data = mindmap_data.get(str(port))
                if mindmap_port_data:
                    link = mindmap_port_data.get('Link')
                    notes = mindmap_port_data.get('Notes')
                    if link:
                        html_content += f"<p>{link}</p>"
                    if notes:
                        html_content += f"<p><strong>Notes:</strong> {notes}</p>"

            html_content += "</div></div>"
        html_content += "</div></div>"

        # Include Vulnerability Info
        html_content += "<div class='collapsible-container'>"
        html_content += "<div class='collapsible' onclick='toggleContent(this)'><span class='vulnerability'><strong>Vulnerability Info</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
        html_content += "<div class='content'>"

        # Color code the entries based on risk level
        risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        risk_colors = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "green"}

        # Sort the vulnerabilities first by criticality label, then by cvss score
        vulnerability_info_sorted = sorted(vulnerability_info.items(), key=lambda x: (risk_order.get(x[1][0][5], 999), -float(x[1][0][2]) if x[1][0][2] and x[1][0][2].replace('.', '', 1).isdigit() else 999), reverse=False)

        # Display the vulnerability info
        for vulnerability_name, vulnerability_data in vulnerability_info_sorted:
            description, cve, cvss, host, ports, risk = vulnerability_data[0]
            unique_hosts_ports = defaultdict(list)

            for _, _, _, host_entry, port_entry, _ in vulnerability_data:
                unique_hosts_ports[host_entry].append(port_entry)

            html_content += f"<div class='collapsible-container-service'><div class='collapsible-service' onclick='toggleContentService(this)'><span class='vulnerability'><strong style='color: {risk_colors.get(risk, 'white')}'>{vulnerability_name} - {risk}</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
            html_content += "<div class='content-service'>"
            html_content += f"<p><strong>Description</strong>: {description}</p>"
            html_content += f"<p><strong>CVE</strong>: {cve}</p>"
            html_content += f"<p><strong>CVSS</strong>: {cvss}</p>"
            html_content += f"<p><strong>Associated Ports</strong>: {', '.join(set(map(str, unique_hosts_ports[host])))}</p>"
            html_content += "<p><strong>Hosts</strong>: <textarea readonly='' rows='4' cols='50'>"
            html_content += "\n".join(unique_hosts_ports.keys())
            html_content += "</textarea></p>"
            html_content += "</div></div>"

        html_content += "</div></div>"  # Close Vulnerability Info section

        
        # Include HTTP(S) Info
        html_content += "<div class='collapsible-container'>"
        html_content += "<div class='collapsible' onclick='toggleContent(this)'><span class='service'><strong>HTTP(S) Info</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
        html_content += "<div class='content'>"

        # Include the "All URLs" section
        all_urls = [url for urls in http_info.values() for url in urls]
        html_content += "<div class='collapsible-container-service'><div class='collapsible-service' onclick='toggleContentService(this)'><span class='service'><strong>All URLs</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
        html_content += "<div class='content-service'>"
        html_content += "<textarea readonly='' rows='20' cols='100'>\n"
        html_content += "\n".join(all_urls)
        html_content += "</textarea>"
        html_content += "<p><code>cat urls.txt | aquatone -out ./aquatone-data</code></p>"
        html_content += "</div></div>"

        # Include HTTP(S) Info
        html_content += "<div class='collapsible-container'>"
        html_content += "<div class='collapsible' onclick='toggleContent(this)'><span class='service'><strong>Directories and HTTP Methods Per Host</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
        html_content += "<div class='content'>"
        
        for host, urls in http_info.items():
            html_content += f"<div class='collapsible-container-service'><div class='collapsible-service' onclick='toggleContentService(this)'><span class='service'><strong>Host: {host}</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
            html_content += "<div class='content-service'>"
            html_content += "<ul class='ip-address'>"
            html_content += "<p><strong>URLs:</strong></p>"
            for url in urls:
                html_content += f"<li>{url}</li>"
            html_content += "</ul>"

            html_content += "</div></div>"
        html_content += "</div></div>"

        # Include the EyeWitness Bash Script. Need to test/update this, currently just works in theory. Probably use aquatone instead.
        bash_script_content = self.generate_bash_script(http_info)
        html_content += "<div class='collapsible-container-service'><div class='collapsible-service' onclick='toggleContentService(this)'><span class='service'><strong>Bash Script for EyeWitness.py</strong></span><span class='icons'><span class='expand-button'></span><span class='collapse-button'></span></span></div>"
        html_content += "<div class='content-service'>"
        html_content += "<p>Checks each URL to see if it returns 200 code, and if it does, it uses eyewitness to capture screenshot of the page. Currently, just experimental and I haven't tested this yet."
        html_content += f"<textarea readonly='' rows='20' cols='100'>{bash_script_content}</textarea>"
        html_content += "</div></div>"
        
        # JavaScript for toggling content
        html_content += """
        <script>
            function toggleContent(element) {
                var content = element.nextElementSibling;
                if (content.style.display === 'block') {
                    content.style.display = 'none';
                } else {
                    content.style.display = 'block';
                }
            }

            function toggleContentService(element) {
                var content = element.nextElementSibling;
                if (content.style.display === 'block') {
                    content.style.display = 'none';
                } else {
                    content.style.display = 'block';
                }
            }

            function expandAllSections() {
                var contents = document.getElementsByClassName('content');
                for (var i = 0; i < contents.length; i++) {
                    contents[i].style.display = 'block';
                }
            }

            function collapseAllSections() {
                var contents = document.getElementsByClassName('content');
                for (var i = 0; i < contents.length; i++) {
                    contents[i].style.display = 'none';
                }
            }
        </script>
        </div></div></div></body></html>
        """

        with open(self.output_path, 'w', encoding='utf-8') as file:
            file.write(html_content)
