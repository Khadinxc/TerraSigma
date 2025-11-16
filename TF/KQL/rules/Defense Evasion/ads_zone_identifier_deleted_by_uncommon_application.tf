resource "azurerm_sentinel_alert_rule_scheduled" "ads_zone_identifier_deleted_by_uncommon_application" {
  name                       = "ads_zone_identifier_deleted_by_uncommon_application"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ADS Zone.Identifier Deleted By Uncommon Application"
  description                = "Detects the deletion of the \"Zone.Identifier\" ADS by an uncommon process. Attackers can leverage this in order to bypass security restrictions that make use of the ADS such as Microsoft Office apps. - Other third party applications not listed."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ":Zone.Identifier" and (not((InitiatingProcessFolderPath in~ ("C:\\Program Files\\PowerShell\\7-preview\\pwsh.exe", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\SysWOW64\\explorer.exe", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")))) and (not(((InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe", "C:\\Program Files\\Mozilla Firefox\\firefox.exe")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}