resource "azurerm_sentinel_alert_rule_scheduled" "service_binary_in_user_controlled_folder" {
  name                       = "service_binary_in_user_controlled_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Service Binary in User Controlled Folder"
  description                = "Detects the setting of the \"ImagePath\" value of a service registry key to a path controlled by a non-administrator user such as \"\\AppData\\\" or \"\\ProgramData\\\". Attackers often use such directories for staging purposes. This rule might also trigger on badly written software, where if an attacker controls an auto starting service, they might achieve persistence or privilege escalation. Note that while ProgramData is a user controlled folder, software might apply strict ACLs which makes them only accessible to admin users. Remove such folders via filters if you experience a lot of noise."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData contains ":\\ProgramData\\" or RegistryValueData contains "\\AppData\\Local\\" or RegistryValueData contains "\\AppData\\Roaming\\") and (RegistryKey contains "ControlSet" and RegistryKey endswith "\\Services*") and RegistryKey endswith "\\ImagePath") and (not((RegistryValueData contains "C:\\ProgramData\\Microsoft\\Windows Defender\\" and (RegistryKey endswith "\\Services\\WinDefend*" or RegistryKey contains "\\Services\\MpKs")))) and (not((((RegistryValueData contains "C:\\Users\\" and RegistryValueData contains "AppData\\Local\\Temp\\MBAMInstallerService.exe") and RegistryKey contains "\\Services\\MBAMInstallerService") or (RegistryValueData contains "C:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe" and RegistryKey contains "\\Services\\ZoomCptService"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1112"]
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}