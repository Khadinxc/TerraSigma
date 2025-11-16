resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_connection_to_active_directory_web_services" {
  name                       = "uncommon_connection_to_active_directory_web_services"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Connection to Active Directory Web Services"
  description                = "Detects uncommon network connections to the Active Directory Web Services (ADWS) from processes not typically associated with ADWS management. - ADWS is used by a number of legitimate applications that need to interact with Active Directory. These applications should be added to the allow-listing to avoid false positives."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemotePort == 9389 and (not((InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\dsac.exe" or InitiatingProcessFolderPath =~ "C:\\Program Files\\Microsoft Monitoring Agent\\" or (InitiatingProcessFolderPath startswith "C:\\Program Files\\PowerShell\\7\\pwsh.exe" or InitiatingProcessFolderPath startswith "C:\\Program Files\\PowerShell\\7-preview\\pwsh.ex" or InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\WindowsPowerShell\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\WindowsPowerShell\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }
}