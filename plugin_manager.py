# Title: Plugin Manager
# Version: 1.0.0
# Author: Connor Fancy

import json
import csv
from helpers.custom_logger import log
import os
import argparse
import atexit
import sys


class PluginManager:
    # Constants
    TEMP_FILE = "temp.json"
    IGNORE_PLUGIN = "11213"
    IGNORE_INFORMATIONAL = "None"

    def __init__(self, config_path, csv_path):
        self.config_path = config_path
        self.csv_path = csv_path
        self.config = self.read_json_file(self.config_path)
        self.findings = self.read_findings_csv(self.csv_path)
        self.temp_changes = {}
        atexit.register(self.cleanup)

    def read_json_file(self, path: str) -> dict:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            log.error(f"File {path} not found.")
            sys.exit(1)

    def write_json_file(self, path: str, data: dict):
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)

    def read_findings_csv(self, path: str) -> list:
        findings = []
        try:
            with open(path, mode='r', encoding='utf-8') as csv_file:
                csv_reader = csv.DictReader(csv_file)
                findings = [
                    {key: row[key] for key in ['Plugin ID', 'Name', 'Risk']}
                    for row in csv_reader if row['Risk'] and row['Risk'].strip()
                ]
        except FileNotFoundError:
            log.error(f"File {path} not found.")
            sys.exit(1)
        return findings


    def identify_merged_findings(self):
        merged_findings = {}
        individual_findings = set()
        plugin_categories = self.build_plugin_categories()
        
        for finding in self.findings:
            plugin_id = finding['Plugin ID']
            name = finding['Name']
            
            if finding['Risk'] == self.IGNORE_INFORMATIONAL:
                continue
            if plugin_id == self.IGNORE_PLUGIN:  # Ignore the "Track/Trace" plugin
                continue
            if plugin_id in plugin_categories:
                if plugin_categories[plugin_id] not in merged_findings:
                    merged_findings[plugin_categories[plugin_id]] = set()
                plugin_info = f"Plugin ID: {plugin_id}, Name: {name}"
                merged_findings[plugin_categories[plugin_id]].add(plugin_info)
            else:
                individual_findings.add(f"Plugin ID: {plugin_id}, Name: {name}")
                
        for category in merged_findings:
            merged_findings[category] = list(merged_findings[category])
        individual_findings = list(individual_findings)
        
        return merged_findings, individual_findings

    def build_plugin_categories(self):
            categories = {}
            for category, details in self.config["plugins"].items():
                for plugin_id in details["ids"]:
                    categories[plugin_id] = category
            return categories

    def confirm_exit(self):
        if self.temp_changes:
            exit_confirm = input('You have pending changes. Do you really want to exit without saving? (y/n): ')
            if exit_confirm.lower() in ['y', 'yes']:
                sys.exit()
        else:
            sys.exit()

    def remove_plugin(self):
        plugin_names = self.get_plugin_names_from_csv()
        categories = list(self.config['plugins'].keys())
        category_name = self._prompt_choice('Select the category from which to remove plugins:', categories + ['Cancel'])

        if category_name == 'Cancel':
            return

        filter_string = input('Enter a filter string to narrow down the plugins (leave empty for all): ').lower()
        current_plugin_ids = self.config['plugins'].get(category_name, {}).get('ids', [])
        filtered_plugins = [
            {'id': plugin_id, 'name': plugin_names[plugin_id]}
            for plugin_id in current_plugin_ids
            if plugin_id in plugin_names and filter_string in plugin_names[plugin_id].lower()
        ]

        if not filtered_plugins:
            log.info("No plugins matched your filter. Please try again with a different filter string.")
            return

        choices_for_plugin_removal = [
            f"{plugin['id']} - {plugin['name']}" for plugin in filtered_plugins
        ]

        selected_plugins = self._prompt_choices('Select the Plugin IDs to remove from \'{}\':'.format(category_name), choices_for_plugin_removal)

        for plugin_selection in selected_plugins:
            plugin_id = plugin_selection.split(" - ")[0]
            if plugin_id in current_plugin_ids:
                current_plugin_ids.remove(plugin_id)
                log.success(f"Removed plugin {plugin_id} from category {category_name}.")
            else:
                log.warning(f"Plugin {plugin_id} not found in category {category_name}.")

        self.temp_changes[category_name] = current_plugin_ids


    def add_plugin(self, non_merged_plugins):
        available_plugins = [plugin for plugin in non_merged_plugins if plugin['id'] not in sum(self.temp_changes.values(), [])]
        available_plugins = sorted(available_plugins, key=lambda x: x['name'])
        choices_for_plugin_selections = [f"{plugin['id']} - {plugin['name']}" for plugin in available_plugins]

        plugin_selections = self._prompt_choices('Select the Plugin IDs to add:', choices_for_plugin_selections)
        category_name = self._prompt_choice('Select a category:', list(self.config['plugins'].keys()) + ['Main Menu'])

        if 'Main Menu' in plugin_selections or category_name == 'Main Menu':
            return

        plugin_ids = [selection.split(" - ")[0] for selection in plugin_selections]

        if plugin_ids and category_name:
            if self.temp_changes is None:
                self.temp_changes = {}

            if category_name not in self.temp_changes:
                self.temp_changes[category_name] = []
            for plugin_id in plugin_ids:
                if plugin_id not in self.temp_changes[category_name]:
                    self.temp_changes[category_name].append(plugin_id)
                    log.success(f"Temporarily added plugin {plugin_id} to category {category_name}. Use 'Write Changes' to save.")
                else:
                    log.warning(f"Plugin {plugin_id} is already in category {category_name}.")

    def _prompt_choice(self, message, choices):
        print(f"\n{message}")
        for i, choice in enumerate(choices, 1):
            print(f"{i}. {choice}")
        while True:
            try:
                selection = int(input(f"Select an option (1-{len(choices)}): "))
                if 1 <= selection <= len(choices):
                    return choices[selection - 1]
                else:
                    print("Invalid selection. Try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    def _prompt_choices(self, message, choices):
        print(f"\n{message}")
        for i, choice in enumerate(choices, 1):
            print(f"{i}. {choice}")
        selections = []
        while True:
            try:
                input_selections = input("Select options by number, separated by commas (e.g., 1,2,3): ").split(',')
                selections = [choices[int(i.strip()) - 1] for i in input_selections if i.strip().isdigit() and 1 <= int(i.strip()) <= len(choices)]
                if selections:
                    return selections
                else:
                    print("No valid selections. Try again.")
            except (IndexError, ValueError):
                print("Invalid input. Please enter valid numbers.")


    def clear_changes(self):
        self.temp_changes.clear()
        log.success("Changes cleared.")

    def view_changes(self):
        log.info("Current Changes:")
        for category, plugin_ids in self.temp_changes.items():
            print(f"\n• {category}:")
            for plugin_id in plugin_ids:
                print(f"  └── {plugin_id}")
        print()

    def write_changes(self):
        self.update_config()
        log.success("Changes written to N2P_config.json.")

    def write_to_temp_file(self, temp_changes):
        with open(self.TEMP_FILE, 'w') as f:
            json.dump(temp_changes, f)

    def update_config(self):
        if not self.temp_changes:
            log.warning("No changes to update.")
            return
        for category, plugin_ids in self.temp_changes.items():
            if category in self.config['plugins']:
                self.config['plugins'][category]['ids'].extend(
                    [pid for pid in plugin_ids if pid not in self.config['plugins'][category]['ids']])
            else:
                log.error(f"Error: The category '{category}' does not exist in the config.")
        self.write_json_file('N2P_config.json', self.config)
        self.temp_changes.clear()

    def cleanup(self):
        if os.path.exists(self.TEMP_FILE):
            os.remove(self.TEMP_FILE)


    def get_plugin_names_from_csv(self) -> dict:
        """Returns a dictionary of plugin names from the CSV file."""
        plugin_names = {}
        try:
            with open(self.csv_path, mode='r', encoding='utf-8') as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    plugin_id = row.get('Plugin ID')
                    name = row.get('Name')
                    if plugin_id and name:
                        plugin_names[plugin_id] = name
        except FileNotFoundError:
            log.error(f"File {self.csv_path} not found.")
            sys.exit(1)
        return plugin_names


    def simulate_findings(self):
        merged_findings, individual_findings = self.identify_merged_findings()
        print("\n" + "=" * 50)
        print("     Simulated Merged and Individual Findings")
        print("=" * 50)
        
        # Display Merged Findings
        print("\nMerged Findings:")
        for category, findings in merged_findings.items():
            print(f"\n• {category}:")
            for finding in findings:
                print(f"  └── {finding}")
        
        # Display Individual Findings
        print("\nIndividual Findings:")
        for finding in individual_findings:
            print(f"  • {finding}")

        print("\n" + "=" * 50)


class ArgParser:
    @staticmethod
    def parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(description='Simulate results for PlexTrac.')
        parser.add_argument('-f', dest='csv_file_path', type=str, help='Path to the CSV file.', required=True)
        return parser.parse_args()


if __name__ == "__main__":
    try:
        args = ArgParser.parse_args()
        manager = PluginManager('N2P_config.json', args.csv_file_path)

        # Identify merged and individual findings
        merged_findings, individual_findings = manager.identify_merged_findings()

        non_merged_plugins = [{'id': finding.split(", ")[0].split(": ")[1],
                            'name': finding.split(", ")[1].split(": ")[1]} for finding in individual_findings]

        # Directly handle CLI interactions
        action_map = {
            'Add Plugin': manager.add_plugin,
            'Simulate Findings': manager.simulate_findings,
            'Remove Plugin': manager.remove_plugin,
            'View Changes': manager.view_changes,
            'Write Changes': manager.write_changes,
            'Clear Changes': manager.clear_changes,
            'Exit': manager.confirm_exit
        }

        while True:
            print("\nSelect an action:")
            for i, action in enumerate(action_map.keys(), 1):
                print(f"{i}. {action}")

            try:
                choice = int(input(f"Select an option (1-{len(action_map)}): "))
                if 1 <= choice <= len(action_map):
                    action = list(action_map.keys())[choice - 1]
                    if action == 'Add Plugin':
                        action_map[action](non_merged_plugins)
                    else:
                        action_map[action]()
                else:
                    print("Invalid selection. Try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")
    
    except KeyboardInterrupt:
        log.error("Keyboard Interrupt. Exiting...")
        sys.exit()
