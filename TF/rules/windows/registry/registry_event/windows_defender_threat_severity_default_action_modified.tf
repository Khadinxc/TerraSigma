resource "azurerm_sentinel_alert_rule_scheduled" "windows_defender_threat_severity_default_action_modified" {
  name                       = "windows_defender_threat_severity_default_action_modified"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Defender Threat Severity Default Action Modified"
  description                = "Detects modifications or creations of Windows Defender's default threat action settings based on severity to 'allow' or take 'no action'. This is a highly suspicious configuration change that effectively disables Defender's ability to automatically mitigate threats of a certain severity level, allowing malicious software to run unimpeded. An attacker might use this technique to bypass defenses before executing payloads. - Legitimate administration via scripts or tools (e.g., SCCM, Intune, GPO enforcement). Correlate with administrative activity. - Software installations that legitimately modify Defender settings (less common for these specific keys)."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData in~ ("DWORD (0x00000006)", "DWORD (0x00000009)")) and RegistryKey endswith "\\Microsoft\\Windows Defender\\Threats\\ThreatSeverityDefaultAction*" and (RegistryKey endswith "\\1" or RegistryKey endswith "\\2" or RegistryKey endswith "\\4" or RegistryKey endswith "\\5")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}