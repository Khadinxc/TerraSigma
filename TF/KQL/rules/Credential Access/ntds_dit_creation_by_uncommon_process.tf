resource "azurerm_sentinel_alert_rule_scheduled" "ntds_dit_creation_by_uncommon_process" {
  name                       = "ntds_dit_creation_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "NTDS.DIT Creation By Uncommon Process"
  description                = "Detects creation of a file named \"ntds.dit\" (Active Directory Database) by an uncommon process or a process located in a suspicious directory"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\ntds.dit" and ((InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe" or InitiatingProcessFolderPath endswith "\\wsl.exe" or InitiatingProcessFolderPath endswith "\\wt.exe") or (InitiatingProcessFolderPath contains "\\AppData\\" or InitiatingProcessFolderPath contains "\\Temp\\" or InitiatingProcessFolderPath contains "\\Public\\" or InitiatingProcessFolderPath contains "\\PerfLogs\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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