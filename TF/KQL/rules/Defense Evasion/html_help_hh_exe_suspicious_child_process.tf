resource "azurerm_sentinel_alert_rule_scheduled" "html_help_hh_exe_suspicious_child_process" {
  name                       = "html_help_hh_exe_suspicious_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HTML Help HH.EXE Suspicious Child Process"
  description                = "Detects a suspicious child process of a Microsoft HTML Help (HH.exe)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\CertReq.exe" or FolderPath endswith "\\CertUtil.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\installutil.exe" or FolderPath endswith "\\MSbuild.exe" or FolderPath endswith "\\MSHTA.EXE" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe") and InitiatingProcessFolderPath endswith "\\hh.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "InitialAccess"]
  techniques                 = ["T1047", "T1059", "T1218", "T1566"]
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