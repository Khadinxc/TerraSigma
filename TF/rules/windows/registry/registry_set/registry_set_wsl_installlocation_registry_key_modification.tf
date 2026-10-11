resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_wsl_installlocation_registry_key_modification" {
  name                       = "registry_set_wsl_installlocation_registry_key_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential WSL InstallLocation Registry Key Modification"
  description                = <<DESC
    Detects modifications to the Windows Subsystem for Linux (WSL) InstallLocation registry key. Attackers can modify this registry key to redirect the execution flow of legitimate WSL processes (wsl.exe or bash.exe) to a malicious payload, acting as a proxy execution and defense evasion technique.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_wsl_installlocation_registry_key_modification.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\Lxss\\MSI\\InstallLocation" and (not((((RegistryValueData in~ ("C:\\Program Files\\WSL", "%ProgramFiles%\\WSL")) or (RegistryValueData contains ":\\Program Files\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_" or RegistryValueData contains "\\AppData\\Local\\Microsoft\\WindowsApps" or RegistryValueData contains "%ProgramFiles%\\WindowsApps\\MicrosoftCorporationII.WindowsSubsystemForLinux_")) or (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1112", "T1218"]
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