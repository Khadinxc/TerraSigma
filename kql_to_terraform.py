#!/usr/bin/env python3
"""
KQL to Terraform Converter
Converts KQL detection rules to Terraform azurerm_sentinel_alert_rule resources
with intelligent entity mapping based on table schemas
"""

import os
import re
import json
import sys
import traceback
from pathlib import Path
from collections import defaultdict


class KQLToTerraform:
    def __init__(self, kql_dir, output_dir, schemas_file, output_structure='source'):
        self.kql_dir = Path(kql_dir)
        self.output_dir = Path(output_dir)
        self.schemas_file = Path(schemas_file)
        self.schemas = self.load_schemas()
        self.stats = {
            'total_files': 0,
            'converted': 0,
            'failed': 0,
            'by_tactic': defaultdict(int)
        }
        self.failures = []  # Track detailed failure information
        # output_structure: 'source' to mirror original Sigma repo paths,
        # 'tactics' to organize by MITRE tactic (legacy behavior)
        self.output_structure = output_structure
        
        # Entity mapping configuration based on Microsoft Sentinel entity reference
        # https://learn.microsoft.com/en-us/azure/sentinel/entities-reference
        self.entity_mappings = {
            'Account': {
                'fields': ['AccountName', 'AccountDomain', 'AccountSid', 'AccountUpn', 
                          'AccountObjectId', 'InitiatingProcessAccountName', 
                          'InitiatingProcessAccountDomain', 'InitiatingProcessAccountSid', 
                          'InitiatingProcessAccountUpn', 'InitiatingProcessAccountObjectId'],
                'identifiers': {
                    'Name': ['AccountName', 'InitiatingProcessAccountName'],
                    'NTDomain': ['AccountDomain', 'InitiatingProcessAccountDomain'],
                    'Sid': ['AccountSid', 'InitiatingProcessAccountSid'],
                    'UPNSuffix': ['AccountUpn', 'InitiatingProcessAccountUpn'],
                    'AadUserId': ['AccountObjectId', 'InitiatingProcessAccountObjectId']
                }
            },
            'Process': {
                'fields': ['ProcessId', 'ProcessCommandLine', 'InitiatingProcessId', 
                          'InitiatingProcessCommandLine', 'ProcessCreationTime',
                          'InitiatingProcessCreationTime'],
                'identifiers': {
                    'ProcessId': ['ProcessId', 'InitiatingProcessId'],
                    'CommandLine': ['ProcessCommandLine', 'InitiatingProcessCommandLine'],
                    'CreationTimeUtc': ['ProcessCreationTime', 'InitiatingProcessCreationTime']
                }
            },
            'File': {
                'fields': ['FileName', 'FolderPath'],
                'identifiers': {
                    'Name': ['FileName'],
                    'Directory': ['FolderPath']
                }
            },
            'Host': {
                'fields': ['DeviceName', 'DeviceId', 'RemoteDeviceName', 'DestinationDeviceName'],
                'identifiers': {
                    'HostName': ['DeviceName', 'RemoteDeviceName', 'DestinationDeviceName'],
                    'AzureID': ['DeviceId']
                }
            },
            'IP': {
                'fields': ['RemoteIP', 'LocalIP', 'IPAddress', 'RemoteIPAddress', 
                          'DestinationIPAddress', 'SenderIPv4', 'SenderIPv6'],
                'identifiers': {
                    'Address': ['RemoteIP', 'LocalIP', 'IPAddress', 'RemoteIPAddress',
                               'DestinationIPAddress', 'SenderIPv4', 'SenderIPv6']
                }
            },
            'RegistryKey': {
                'fields': ['RegistryKey'],
                'identifiers': {
                    'Key': ['RegistryKey']
                }
            },
            'RegistryValue': {
                'fields': ['RegistryValueName', 'RegistryValueData', 'RegistryValueType'],
                'identifiers': {
                    'Name': ['RegistryValueName'],
                    'Value': ['RegistryValueData'],
                    'ValueType': ['RegistryValueType']
                }
            },
            'URL': {
                'fields': ['RemoteUrl', 'FileOriginUrl'],
                'identifiers': {
                    'Url': ['RemoteUrl', 'FileOriginUrl']
                }
            }
        }
    
    def load_schemas(self):
        """Load table schemas from JSON file"""
        try:
            with open(self.schemas_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading schemas: {e}")
            return {}
    
    def parse_kql_file(self, file_path):
        """Parse KQL file and extract metadata and query"""
        metadata = {}
        query_lines = []
        in_query = False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line_stripped = line.strip()
                
                # Parse metadata from comments
                if line_stripped.startswith('//'):
                    comment = line_stripped[2:].strip()
                    
                    if comment.startswith('Title:'):
                        metadata['title'] = comment[6:].strip()
                    elif comment.startswith('Author:'):
                        metadata['author'] = comment[7:].strip()
                    elif comment.startswith('Date:'):
                        metadata['date'] = comment[5:].strip()
                    elif comment.startswith('Level:'):
                        metadata['level'] = comment[6:].strip()
                    elif comment.startswith('Description:'):
                        metadata['description'] = comment[12:].strip()
                    elif comment.startswith('MITRE Tactic:'):
                        metadata['tactic'] = comment[13:].strip()
                    elif comment.startswith('Tags:'):
                        metadata['tags'] = comment[5:].strip()
                    elif comment.startswith('False Positives:'):
                        continue
                    elif 'description' in metadata and not any(x in comment for x in ['MITRE', 'Tags:', 'False']):
                        # Multi-line description
                        metadata['description'] += ' ' + comment
                
                # Detect start of query
                elif not in_query and any(table in line for table in self.schemas.keys()):
                    in_query = True
                    query_lines.append(line.rstrip())
                
                # Collect query lines
                elif in_query:
                    query_lines.append(line.rstrip())
            
            metadata['query'] = '\n'.join(query_lines).strip()
            
            # Extract table name from query
            metadata['table'] = self.extract_table_name(metadata.get('query', ''))
            
            # Extract tactics and techniques from tags
            if 'tags' in metadata:
                metadata['tactics'], metadata['techniques'] = self.parse_tags(metadata['tags'])
            
            return metadata
            
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None
    
    def extract_table_name(self, query):
        """Extract table name from KQL query"""
        for table in self.schemas.keys():
            if table in query:
                return table
        return None
    
    def parse_tags(self, tags_str):
        """Parse MITRE tactics and techniques from tags"""
        tactics = []
        techniques = []
        
        # Map of Sigma tactics to Sentinel tactics
        tactic_map = {
            'attack.reconnaissance': 'Reconnaissance',
            'attack.resource-development': 'ResourceDevelopment',
            'attack.resource_development': 'ResourceDevelopment',
            'attack.initial-access': 'InitialAccess',
            'attack.initial_access': 'InitialAccess',
            'attack.execution': 'Execution',
            'attack.persistence': 'Persistence',
            'attack.privilege-escalation': 'PrivilegeEscalation',
            'attack.privilege_escalation': 'PrivilegeEscalation',
            'attack.defense-evasion': 'DefenseEvasion',
            'attack.defense_evasion': 'DefenseEvasion',
            'attack.credential-access': 'CredentialAccess',
            'attack.credential_access': 'CredentialAccess',
            'attack.discovery': 'Discovery',
            'attack.lateral-movement': 'LateralMovement',
            'attack.lateral_movement': 'LateralMovement',
            'attack.collection': 'Collection',
            'attack.command-and-control': 'CommandAndControl',
            'attack.command_and_control': 'CommandAndControl',
            'attack.exfiltration': 'Exfiltration',
            'attack.impact': 'Impact'
        }
        
        tags_list = [t.strip() for t in tags_str.split(',')]
        
        for tag in tags_list:
            tag_lower = tag.lower()
            
            # Check for tactics
            if tag_lower in tactic_map:
                sentinel_tactic = tactic_map[tag_lower]
                if sentinel_tactic not in tactics:
                    tactics.append(sentinel_tactic)
            
            # Check for techniques (T####)
            technique_match = re.search(r'attack\.t\d{4}(?:\.\d{3})?', tag_lower)
            if technique_match:
                technique = technique_match.group(0).replace('attack.', '').upper()
                # Strip subtechnique to parent (T1560.001 -> T1560)
                # Terraform only supports parent techniques
                parent_technique = technique.split('.')[0]
                if parent_technique not in techniques:
                    techniques.append(parent_technique)
        
        return tactics, techniques
    
    def generate_entity_mappings(self, query, table_name):
        """Generate entity mappings based on query content and table schema"""
        if not table_name or table_name not in self.schemas:
            return []
        
        table_fields = self.schemas[table_name].get('common_fields', [])
        entity_mappings = []
        
        # Priority order: Account, Host, IP must always be included if available
        priority_entities = ['Account', 'Host', 'IP']
        other_entities = [e for e in self.entity_mappings.keys() if e not in priority_entities]
        ordered_entities = priority_entities + other_entities
        
        # Analyze query to find which fields are used
        query_lower = query.lower()
        
        for entity_type in ordered_entities:
            if entity_type not in self.entity_mappings:
                continue
                
            config = self.entity_mappings[entity_type]
            field_mappings = []
            
            for identifier, field_names in config['identifiers'].items():
                for field_name in field_names:
                    # For Account, Host, IP: always add if field exists in table
                    # For others: only add if field is referenced in query
                    if field_name in table_fields:
                        if entity_type in priority_entities or field_name.lower() in query_lower:
                            field_mappings.append({
                                'identifier': identifier,
                                'column_name': field_name
                            })
                            break  # Only add one field per identifier
            
            # Add entity mapping if we found any fields
            if field_mappings:
                entity_mappings.append({
                    'entity_type': entity_type,
                    'field_mappings': field_mappings
                })
        
        return entity_mappings
    
    def format_terraform_resource(self, metadata, resource_name, file_stem):
        """Generate Terraform resource code"""
        tf_lines = []
        
        # Resource declaration
        tf_lines.append(f'resource "azurerm_sentinel_alert_rule_scheduled" "{resource_name}" {{')
        tf_lines.append(f'  name                       = "{resource_name}"')
        tf_lines.append(f'  log_analytics_workspace_id = var.workspace_id')
        
        # Display name
        if metadata.get('title'):
            tf_lines.append(f'  display_name               = "{self.escape_terraform_string(metadata["title"])}"')
        
        # Description
        if metadata.get('description'):
            desc = self.escape_terraform_string(metadata['description'])
            tf_lines.append(f'  description                = "{desc}"')
        
        # Severity
        severity_map = {
            'informational': 'Informational',
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'High'  # Map critical to High as Sentinel doesn't have Critical
        }
        severity = severity_map.get(metadata.get('level', 'medium').lower(), 'Medium')
        tf_lines.append(f'  severity                   = "{severity}"')
        
        # Query
        if metadata.get('query'):
            tf_lines.append('  query                      = <<QUERY')
            # Escape Terraform interpolation sequences in the query
            escaped_query = self.escape_terraform_heredoc(metadata['query'])
            tf_lines.append(escaped_query)
            tf_lines.append('QUERY')
        
        # Scheduled rule specific fields
        tf_lines.append('  query_frequency            = "PT1H"')
        tf_lines.append('  query_period               = "PT1H"')
        tf_lines.append('  trigger_operator           = "GreaterThan"')
        tf_lines.append('  trigger_threshold          = 0')
        tf_lines.append('  suppression_enabled        = false')
        tf_lines.append('  suppression_duration       = "PT5H"')
        
        # Tactics
        if metadata.get('tactics'):
            tactics_str = '", "'.join(metadata['tactics'])
            tf_lines.append(f'  tactics                    = ["{tactics_str}"]')
        
        # Techniques
        if metadata.get('techniques'):
            techniques_str = '", "'.join(metadata['techniques'])
            tf_lines.append(f'  techniques                 = ["{techniques_str}"]')
        
        tf_lines.append('  enabled                    = true')
        
        # Incident configuration
        tf_lines.append('')
        tf_lines.append('  incident {')
        tf_lines.append('    create_incident_enabled = true')
        tf_lines.append('    grouping {')
        tf_lines.append('      enabled                 = false')
        tf_lines.append('      lookback_duration       = "PT5H"')
        tf_lines.append('      reopen_closed_incidents = false')
        tf_lines.append('      entity_matching_method  = "AllEntities"')
        tf_lines.append('      by_entities             = []')
        tf_lines.append('      by_alert_details        = []')
        tf_lines.append('      by_custom_details       = []')
        tf_lines.append('    }')
        tf_lines.append('  }')
        
        # Event grouping
        tf_lines.append('')
        tf_lines.append('  event_grouping {')
        tf_lines.append('    aggregation_method = "SingleAlert"')
        tf_lines.append('  }')
        
        # Entity mappings
        entity_mappings = self.generate_entity_mappings(
            metadata.get('query', ''),
            metadata.get('table')
        )
        
        for entity_mapping in entity_mappings:
            tf_lines.append('')
            tf_lines.append('  entity_mapping {')
            tf_lines.append(f'    entity_type = "{entity_mapping["entity_type"]}"')
            
            for field_mapping in entity_mapping['field_mappings']:
                tf_lines.append('    field_mapping {')
                tf_lines.append(f'      identifier  = "{field_mapping["identifier"]}"')
                tf_lines.append(f'      column_name = "{field_mapping["column_name"]}"')
                tf_lines.append('    }')
            
            tf_lines.append('  }')
        
        tf_lines.append('}')
        
        return '\n'.join(tf_lines)
    
    def escape_terraform_string(self, text):
        """Escape special characters in Terraform strings"""
        if not text:
            return ""
        # Escape backslashes and quotes
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        # Remove any control characters
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
        return text
    
    def escape_terraform_heredoc(self, text):
        """Escape Terraform interpolation sequences in heredoc (query) strings"""
        if not text:
            return ""
        # Escape Terraform interpolation sequences
        # ${...} becomes $${...}
        text = text.replace('${', '$${')
        # %{...} becomes %%{...}
        text = text.replace('%{', '%%{')
        return text
    
    def sanitize_resource_name(self, name):
        """Convert name to valid Terraform resource name"""
        # Remove invalid characters
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        # Remove leading/trailing underscores
        clean_name = clean_name.strip('_')
        # Remove duplicate underscores
        clean_name = re.sub(r'_+', '_', clean_name)
        # Lowercase
        clean_name = clean_name.lower()
        # Ensure doesn't start with number
        if clean_name and clean_name[0].isdigit():
            clean_name = 'rule_' + clean_name
        return clean_name
    
    def convert_file(self, kql_file, relative_path):
        """Convert a single KQL file to Terraform"""
        try:
            # Parse KQL file
            metadata = self.parse_kql_file(kql_file)
            if not metadata or not metadata.get('query'):
                print(f"Skipping {relative_path} - no query found")
                return False
            
            # Compute output directory based on desired output structure
            # Option 'source' mirrors the original Sigma repo folder structure
            # Option 'tactics' groups rules by first MITRE tactic (legacy)
            if self.output_structure == 'source':
                # Remove leading 'KQL' folder from path if present
                path_parts = relative_path.parts
                if path_parts and path_parts[0].upper() == 'KQL':
                    relative_path = Path(*path_parts[1:])

                # Preserve the source folder structure under output_dir
                output_subdir = self.output_dir / relative_path.parent
            else:
                # Group by first tactic if available, otherwise fallback to source path
                tactic_folder = None
                if metadata.get('tactics') and len(metadata['tactics']) > 0:
                    tactic_folder = metadata['tactics'][0]

                if tactic_folder:
                    output_subdir = self.output_dir / 'rules' / tactic_folder
                else:
                    # Fallback to preserving source structure
                    path_parts = relative_path.parts
                    if path_parts and path_parts[0].upper() == 'KQL':
                        relative_path = Path(*path_parts[1:])
                    output_subdir = self.output_dir / relative_path.parent

            output_subdir.mkdir(parents=True, exist_ok=True)
            
            # Generate resource name from file stem
            file_stem = kql_file.stem
            resource_name = self.sanitize_resource_name(file_stem)
            
            # Generate Terraform code
            tf_code = self.format_terraform_resource(metadata, resource_name, file_stem)
            
            # Write to file
            output_file = output_subdir / f"{file_stem}.tf"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(tf_code)
            
            # Update stats
            self.stats['converted'] += 1
            if metadata.get('tactic'):
                self.stats['by_tactic'][metadata['tactic']] += 1
            
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
        """Convert all KQL files in the directory"""
        print("Starting KQL to Terraform conversion...\n")
        print(f"Input directory:  {self.kql_dir}")
        print(f"Output directory: {self.output_dir}")
        print(f"Schemas loaded:   {len(self.schemas)} tables\n")
        print("="*80 + "\n")
        
        # Find all KQL files
        kql_files = list(self.kql_dir.rglob('*.kql'))
        self.stats['total_files'] = len(kql_files)
        
        print(f"Found {len(kql_files)} KQL files\n")
        
        # Process each file
        for kql_file in sorted(kql_files):
            relative_path = kql_file.relative_to(self.kql_dir)
            self.convert_file(kql_file, relative_path)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print conversion summary"""
        print("\n" + "="*80)
        print("CONVERSION SUMMARY")
        print("="*80 + "\n")
        
        print(f"Total KQL files:     {self.stats['total_files']}")
        print(f"Successfully converted: {self.stats['converted']}")
        print(f"Failed:              {self.stats['failed']}\n")
        
        if self.stats['by_tactic']:
            print("Conversions by MITRE Tactic:")
            for tactic, count in sorted(self.stats['by_tactic'].items()):
                print(f"  {tactic:25} {count:4} rules")
        
        success_rate = (self.stats['converted'] / self.stats['total_files'] * 100) if self.stats['total_files'] > 0 else 0
        print(f"\n{'='*80}")
        
        # Write failures to JSON file if any
        if self.failures:
            failures_file = Path("conversion_failures_kql_to_tf.json")
            with open(failures_file, 'w', encoding='utf-8') as f:
                json.dump(self.failures, f, indent=2)
            print(f"[WARNING] {len(self.failures)} conversion failure(s) logged to {failures_file}", file=sys.stderr)
        print(f"Success Rate: {success_rate:.2f}%")
        print(f"{'='*80}\n")
        
        print(f"Output location: {self.output_dir}")
        print("Terraform files ready for deployment!\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Convert KQL detection rules to Terraform format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python kql_to_terraform.py
  python kql_to_terraform.py --kql-dir ./KQL --output-dir ./TF
  python kql_to_terraform.py -i ../Sigma2KQL/KQL -o ../TerraformRules
        """
    )
    parser.add_argument(
        '--kql-dir', '-i',
        type=str,
        default='./KQL',
        help='Path to the KQL rules directory (default: ./KQL)'
    )
    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        default='./TF',
        help='Path to the output directory for Terraform files (default: ./TF)'
    )
    parser.add_argument(
        '--schemas', '-s',
        type=str,
        default='./schemas.json',
        help='Path to the schemas JSON file (default: ./schemas.json)'
    )
    parser.add_argument(
        '--output-structure',
        choices=['source', 'tactics'],
        default='source',
        help='How to structure the output folders: "source" mirrors the source repo structure, "tactics" groups rules by MITRE tactic (default: source)'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    kql_dir = Path(args.kql_dir)
    if not kql_dir.exists():
        print(f"Error: KQL directory not found: {kql_dir}")
        return 1
    
    schemas_file = Path(args.schemas)
    if not schemas_file.exists():
        print(f"Error: Schemas file not found: {schemas_file}")
        return 1
    
    # Create converter and run
    converter = KQLToTerraform(args.kql_dir, args.output_dir, args.schemas, output_structure=args.output_structure)
    converter.convert_all()
    
    return 0 if converter.stats['failed'] == 0 else 1


if __name__ == '__main__':
    exit(main())
