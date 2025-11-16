resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_child_process_of_veeam_dabatase" {
  name                       = "suspicious_child_process_of_veeam_dabatase"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process Of Veeam Dabatase"
  description                = "Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine contains "VEEAMSQL" and InitiatingProcessFolderPath endswith "\\sqlservr.exe") and (((ProcessCommandLine contains "-ex " or ProcessCommandLine contains "bypass" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "DownloadString" or ProcessCommandLine contains "http://" or ProcessCommandLine contains "https://" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "wscript" or ProcessCommandLine contains "copy ") and (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wsl.exe" or FolderPath endswith "\\wt.exe")) or (FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe" or FolderPath endswith "\\netstat.exe" or FolderPath endswith "\\nltest.exe" or FolderPath endswith "\\ping.exe" or FolderPath endswith "\\tasklist.exe" or FolderPath endswith "\\whoami.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Persistence", "PrivilegeEscalation"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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