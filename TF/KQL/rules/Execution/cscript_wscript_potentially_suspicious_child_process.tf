resource "azurerm_sentinel_alert_rule_scheduled" "cscript_wscript_potentially_suspicious_child_process" {
  name                       = "cscript_wscript_potentially_suspicious_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cscript/Wscript Potentially Suspicious Child Process"
  description                = "Detects potentially suspicious child processes of Wscript/Cscript. These include processes such as rundll32 with uncommon exports or PowerShell spawning rundll32 or regsvr32. Malware such as Pikabot and Qakbot were seen using similar techniques as well as many others. - Some false positives might occur with admin or third party software scripts. Investigate and apply additional filters accordingly."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\wscript.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe") and (FolderPath endswith "\\rundll32.exe" or ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") and ((ProcessCommandLine contains "mshta" and ProcessCommandLine contains "http") or (ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "msiexec")))) and (not(((ProcessCommandLine contains "UpdatePerUserSystemParameters" or ProcessCommandLine contains "PrintUIEntry" or ProcessCommandLine contains "ClearMyTracksByProcess") and FolderPath endswith "\\rundll32.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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