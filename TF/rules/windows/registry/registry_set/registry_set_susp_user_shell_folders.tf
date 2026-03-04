resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_susp_user_shell_folders" {
  name                       = "registry_set_susp_user_shell_folders"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Modify User Shell Folders Startup Value"
  description                = "Detect modification of the User Shell Folders registry values for Startup or Common Startup which could indicate persistence attempts. Attackers may modify User Shell Folders registry keys to point to malicious executables or scripts that will be executed during startup. This technique is often used to maintain persistence on a compromised system by ensuring that the malicious payload is executed automatically. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_user_shell_folders.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_susp_user_shell_folders.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey contains "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" or RegistryKey contains "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders") and (RegistryKey endswith "\\Common Startup" or RegistryKey endswith "\\Startup")) and (not((isnull(RegistryValueData) or (RegistryValueData contains "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" or RegistryValueData contains "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") or (RegistryValueData contains "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" or RegistryValueData contains "%%USERPROFILE%%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") or (RegistryValueData contains "C:\\Users\\" and RegistryValueData contains "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1547"]
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