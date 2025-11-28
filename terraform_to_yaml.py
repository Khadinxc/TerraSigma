#!/usr/bin/env python3
"""
Terraform to Sentinel YAML Converter
Converts Terraform azurerm_sentinel_alert_rule resources to Azure Sentinel YAML format
"""

import os
import re
import sys
import uuid
import yaml
import json
import traceback
from pathlib import Path
from collections import defaultdict


class TerraformToYAML:
    def __init__(self, tf_dir, output_dir, output_structure='source'):
        self.tf_dir = Path(tf_dir)
        self.output_dir = Path(output_dir)
        # output_structure: 'source' to mirror TF folder structure, 'tactics' to group by MITRE tactic
        self.output_structure = output_structure
        self.stats = {
            'total_files': 0,
            'converted': 0,
            'failed': 0,
            'by_tactic': defaultdict(int)
        }
        self.failures = []  # Track detailed failure information
        
        # Severity mapping from Terraform to YAML
        self.severity_map = {
            'Informational': 'Informational',
            'Low': 'Low',
            'Medium': 'Medium',
            'High': 'High'
        }
        
        # MITRE Tactic mapping to proper names
        self.tactic_map = {
            'Reconnaissance': 'Reconnaissance',
            'ResourceDevelopment': 'ResourceDevelopment',
            'InitialAccess': 'InitialAccess',
            'Execution': 'Execution',
            'Persistence': 'Persistence',
            'PrivilegeEscalation': 'PrivilegeEscalation',
            'DefenseEvasion': 'DefenseEvasion',
            'CredentialAccess': 'CredentialAccess',
            'Discovery': 'Discovery',
            'LateralMovement': 'LateralMovement',
            'Collection': 'Collection',
            'CommandAndControl': 'CommandAndControl',
            'Exfiltration': 'Exfiltration',
            'Impact': 'Impact'
        }
        
        # Entity type mapping
        self.entity_type_map = {
            'Account': 'Account',
            'Process': 'Process',
            'File': 'File',
            'Host': 'Host',
            'IP': 'IP',
            'Registry': 'RegistryKey',
            'URL': 'URL'
        }
    
    def parse_terraform_file(self, tf_file):
        """Parse Terraform file and extract resource configuration"""
        try:
            with open(tf_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract resource block
            resource_match = re.search(
                r'resource\s+"azurerm_sentinel_alert_rule_scheduled"\s+"([^"]+)"\s*\{(.*)\}',
                content,
                re.DOTALL
            )
            
            if not resource_match:
                return None
            
            resource_name = resource_match.group(1)
            resource_body = resource_match.group(2)
            
            config = {
                'resource_name': resource_name,
                'entity_mappings': []
            }
            
            # Extract simple fields
            config['name'] = self.extract_field(resource_body, 'name')
            config['display_name'] = self.extract_field(resource_body, 'display_name')
            config['description'] = self.extract_field(resource_body, 'description')
            config['severity'] = self.extract_field(resource_body, 'severity')
            config['query_frequency'] = self.extract_field(resource_body, 'query_frequency')
            config['query_period'] = self.extract_field(resource_body, 'query_period')
            config['trigger_operator'] = self.extract_field(resource_body, 'trigger_operator')
            config['trigger_threshold'] = self.extract_field(resource_body, 'trigger_threshold')
            
            # Extract query from heredoc
            query_match = re.search(r'query\s*=\s*<<QUERY\n(.*?)\nQUERY', resource_body, re.DOTALL)
            if query_match:
                query = query_match.group(1)
                # Unescape Terraform interpolation sequences
                query = query.replace('$${', '${')
                query = query.replace('%%{', '%{')
                config['query'] = query.strip()
            
            # Extract tactics (array)
            tactics_match = re.search(r'tactics\s*=\s*\[(.*?)\]', resource_body)
            if tactics_match:
                tactics_str = tactics_match.group(1)
                config['tactics'] = [
                    t.strip().strip('"') for t in tactics_str.split(',') if t.strip()
                ]
            
            # Extract techniques (array)
            techniques_match = re.search(r'techniques\s*=\s*\[(.*?)\]', resource_body)
            if techniques_match:
                techniques_str = techniques_match.group(1)
                config['techniques'] = [
                    t.strip().strip('"') for t in techniques_str.split(',') if t.strip()
                ]
            
            # Extract entity mappings
            config['entity_mappings'] = self.extract_entity_mappings(resource_body)
            
            return config
            
        except Exception as e:
            print(f"Error parsing {tf_file}: {e}")
            return None
    
    def extract_field(self, content, field_name):
        """Extract a simple field value from Terraform content"""
        # Handle string fields - need to account for escaped quotes
        # Pattern: field_name = "...string with possible \" escaped quotes..."
        match = re.search(rf'{field_name}\s*=\s*"((?:[^"\\]|\\.)*)"', content)
        if match:
            # Unescape the string (convert \" back to ")
            value = match.group(1)
            value = value.replace('\\"', '"')
            value = value.replace('\\\\', '\\')
            return value
        
        # Handle numeric fields
        match = re.search(rf'{field_name}\s*=\s*(\d+)', content)
        if match:
            return int(match.group(1))
        
        return None
    
    def extract_entity_mappings(self, content):
        """Extract entity mappings from Terraform content"""
        entity_mappings = []
        
        # Find all entity_mapping blocks using a balanced brace approach
        # Match entity_mapping { ... } allowing nested braces
        pattern = r'entity_mapping\s*\{((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}'
        entity_blocks = re.finditer(pattern, content, re.DOTALL)
        
        for block in entity_blocks:
            block_content = block.group(1)
            
            # Extract entity type
            entity_type_match = re.search(r'entity_type\s*=\s*"([^"]+)"', block_content)
            if not entity_type_match:
                continue
            
            entity_type = entity_type_match.group(1)
            
            # Extract field mappings
            field_mappings = []
            field_blocks = re.finditer(
                r'field_mapping\s*\{([^}]+)\}',
                block_content,
                re.DOTALL
            )
            
            for field_block in field_blocks:
                field_content = field_block.group(1)
                
                identifier_match = re.search(r'identifier\s*=\s*"([^"]+)"', field_content)
                column_match = re.search(r'column_name\s*=\s*"([^"]+)"', field_content)
                
                if identifier_match and column_match:
                    field_mappings.append({
                        'identifier': identifier_match.group(1),
                        'columnName': column_match.group(1)
                    })
            
            if field_mappings:
                entity_mappings.append({
                    'entityType': self.entity_type_map.get(entity_type, entity_type),
                    'fieldMappings': field_mappings
                })
        
        return entity_mappings
    
    def convert_to_yaml(self, config, original_filename):
        """Convert Terraform config to Sentinel YAML format"""
        
        # Generate a deterministic UUID based on the file name
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, config.get('resource_name', original_filename)))
        
        yaml_data = {
            'id': rule_id,
            'name': config.get('display_name') or config.get('name') or config.get('resource_name'),
            'description': config.get('description') or 'No description provided',
            'severity': self.severity_map.get(config.get('severity', 'Medium'), 'Medium'),
            'queryFrequency': config.get('query_frequency', 'PT1H'),
            'queryPeriod': config.get('query_period', 'PT1H'),
            'triggerOperator': self.convert_trigger_operator(config.get('trigger_operator', 'GreaterThan')),
            'triggerThreshold': config.get('trigger_threshold', 0),
            'tactics': self.convert_tactics(config.get('tactics', [])),
            'query': config.get('query', ''),
            'version': '1.0.0',
            'kind': 'Scheduled'
        }
        
        # Add techniques if present
        if config.get('techniques'):
            yaml_data['relevantTechniques'] = config.get('techniques')
        
        # Add entity mappings if present
        if config.get('entity_mappings'):
            yaml_data['entityMappings'] = config.get('entity_mappings')
        
        # Add required data connectors based on query content
        yaml_data['requiredDataConnectors'] = self.detect_data_connectors(config.get('query', ''))
        
        return yaml_data
    
    def convert_trigger_operator(self, operator):
        """Convert Terraform trigger operator to YAML format"""
        operator_map = {
            'GreaterThan': 'gt',
            'LessThan': 'lt',
            'Equal': 'eq',
            'NotEqual': 'ne'
        }
        return operator_map.get(operator, 'gt')
    
    def convert_tactics(self, tactics):
        """Convert Terraform tactics to YAML format"""
        return [self.tactic_map.get(t, t) for t in tactics]
    
    def detect_data_connectors(self, query):
        """Detect required data connectors based on query content"""
        connectors = []
        
        # Map tables to data connectors
        table_connector_map = {
            'DeviceProcessEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceProcessEvents']
            },
            'DeviceFileEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceFileEvents']
            },
            'DeviceRegistryEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceRegistryEvents']
            },
            'DeviceNetworkEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceNetworkEvents']
            },
            'DeviceEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceEvents']
            },
            'DeviceImageLoadEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceImageLoadEvents']
            },
            'DeviceLogonEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceLogonEvents']
            },
            'IdentityLogonEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['IdentityLogonEvents']
            },
            'EmailEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['EmailEvents']
            },
            'CloudAppEvents': {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['CloudAppEvents']
            }
        }
        
        # Check which tables are used in the query
        for table, connector_info in table_connector_map.items():
            if table in query:
                if connector_info not in connectors:
                    connectors.append(connector_info)
        
        return connectors if connectors else [
            {
                'connectorId': 'MicrosoftThreatProtection',
                'dataTypes': ['DeviceProcessEvents']
            }
        ]
    
    def convert_file(self, tf_file, relative_path):
        """Convert a single Terraform file to YAML"""
        try:
            # Parse Terraform file
            config = self.parse_terraform_file(tf_file)
            if not config:
                print(f"Skipping {relative_path} - could not parse")
                self.stats['failed'] += 1
                return False
            
            # Convert to YAML
            yaml_data = self.convert_to_yaml(config, tf_file.stem)
            
            # Determine output directory
            if self.output_structure == 'source':
                # Preserve the source TF folder structure under output_dir
                output_subdir = self.output_dir / relative_path.parent
            else:
                # Group by first tactic if available, otherwise fallback to source path
                tactic_folder = None
                yaml_data = self.convert_to_yaml(config, tf_file.stem)
                if yaml_data.get('tactics') and len(yaml_data['tactics']) > 0:
                    tactic_folder = yaml_data['tactics'][0]

                if tactic_folder:
                    output_subdir = self.output_dir / 'rules' / tactic_folder
                else:
                    output_subdir = self.output_dir / relative_path.parent

            output_subdir.mkdir(parents=True, exist_ok=True)
            
            # Write YAML file
            output_file = output_subdir / f"{tf_file.stem}.yaml"
            
            # Custom YAML representer for multiline strings
            def str_representer(dumper, data):
                if '\n' in data:
                    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
                return dumper.represent_scalar('tag:yaml.org,2002:str', data)
            
            yaml.add_representer(str, str_representer)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(
                    yaml_data,
                    f,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                    width=1000
                )
            
            # Update stats
            self.stats['converted'] += 1
            if yaml_data.get('tactics'):
                for tactic in yaml_data['tactics']:
                    self.stats['by_tactic'][tactic] += 1
            
            return True
            
        except Exception as e:
            error_detail = {
                "file": str(relative_path),
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            self.failures.append(error_detail)
            self.stats['failed'] += 1
            return False
    
    def convert_all(self):
        """Convert all Terraform files in the directory"""
        print(f"Starting Terraform to YAML conversion...\n")
        print(f"Input directory:  {self.tf_dir}")
        print(f"Output directory: {self.output_dir}\n")
        print("="*80 + "\n")
        
        # Find all .tf files
        tf_files = list(self.tf_dir.rglob('*.tf'))
        self.stats['total_files'] = len(tf_files)
        
        print(f"Found {len(tf_files)} Terraform files\n")
        
        # Process each file
        for tf_file in sorted(tf_files):
            relative_path = tf_file.relative_to(self.tf_dir)
            self.convert_file(tf_file, relative_path)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print conversion summary"""
        print("\n" + "="*80)
        print(f"CONVERSION SUMMARY")
        print("="*80 + "\n")
        
        print(f"Total Terraform files: {self.stats['total_files']}")
        print(f"Successfully converted:  {self.stats['converted']}")
        print(f"Failed:                  {self.stats['failed']}\n")
        
        if self.stats['by_tactic']:
            print("Conversions by MITRE Tactic:")
            for tactic, count in sorted(self.stats['by_tactic'].items()):
                print(f"  {tactic:25} {count:4} rules")
        
        success_rate = (self.stats['converted'] / self.stats['total_files'] * 100) if self.stats['total_files'] > 0 else 0
        print(f"\n{'='*80}")
        print(f"Success Rate: {success_rate:.2f}%")
        print(f"{'='*80}\n")
        
        print(f"Output location: {self.output_dir}")
        print(f"YAML files ready for Azure Sentinel deployment!\n")
        
        # Write failures to JSON file if any
        if self.failures:
            failures_file = Path("conversion_failures_tf_to_yaml.json")
            with open(failures_file, 'w', encoding='utf-8') as f:
                json.dump(self.failures, f, indent=2)
            print(f"[WARNING] {len(self.failures)} conversion failure(s) logged to {failures_file}", file=sys.stderr)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Convert Terraform Sentinel rules to YAML format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python terraform_to_yaml.py
  python terraform_to_yaml.py --tf-dir ./TF --output-dir ./YAML
  python terraform_to_yaml.py -i ./TF -o ./SentinelRules
        """
    )
    parser.add_argument(
        '--tf-dir', '-i',
        type=str,
        default='./TF',
        help='Path to the Terraform rules directory (default: ./TF)'
    )
    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        default='./YAML',
        help='Path to the output directory for YAML files (default: ./YAML)'
    )
    parser.add_argument(
        '--output-structure',
        choices=['source', 'tactics'],
        default='source',
        help='How to structure the output folders: "source" mirrors the TF source structure, "tactics" groups rules by MITRE tactic (default: source)'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    tf_dir = Path(args.tf_dir)
    if not tf_dir.exists():
        print(f"Error: Terraform directory not found: {tf_dir}")
        return 1
    
    # Create converter and run
    converter = TerraformToYAML(args.tf_dir, args.output_dir, output_structure=args.output_structure)
    converter.convert_all()
    
    return 0 if converter.stats['failed'] == 0 else 1


if __name__ == '__main__':
    exit(main())
