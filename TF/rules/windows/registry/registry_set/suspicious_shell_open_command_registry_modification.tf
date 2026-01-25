resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_shell_open_command_registry_modification" {
  name                       = "suspicious_shell_open_command_registry_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Shell Open Command Registry Modification"
  description                = "Detects modifications to shell open registry keys that point to suspicious locations typically used by malware for persistence. Generally, modifications to the `*\\shell\\open\\command` registry key can indicate an attempt to change the default action for opening files, and various UAC bypass or persistence techniques involve modifying these keys to execute malicious scripts or binaries. - Legitimate software installations or updates that modify the shell open command registry keys to these locations."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "\\$Recycle.Bin\\" or RegistryValueData contains "\\AppData\\Local\\Temp\\" or RegistryValueData contains "\\Contacts\\" or RegistryValueData contains "\\Music\\" or RegistryValueData contains "\\PerfLogs\\" or RegistryValueData contains "\\Photos\\" or RegistryValueData contains "\\Pictures\\" or RegistryValueData contains "\\Users\\Public\\" or RegistryValueData contains "\\Videos\\" or RegistryValueData contains "\\Windows\\Temp\\" or RegistryValueData contains "%AppData%" or RegistryValueData contains "%LocalAppData%" or RegistryValueData contains "%Temp%" or RegistryValueData contains "%tmp%") and RegistryKey endswith "\\shell\\open\\command*"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1548", "T1546"]
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