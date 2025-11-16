resource "azurerm_sentinel_alert_rule_scheduled" "scripting_commandline_process_spawned_regsvr32" {
  name                       = "scripting_commandline_process_spawned_regsvr32"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scripting/CommandLine Process Spawned Regsvr32"
  description                = "Detects various command line and scripting engines/processes such as \"PowerShell\", \"Wscript\", \"Cmd\", etc. spawning a \"regsvr32\" instance. - Legitimate \".bat\", \".hta\", \".ps1\" or \".vbs\" scripts leverage legitimately often. Apply additional filter and exclusions as necessary - Some legitimate Windows services"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\regsvr32.exe" and (InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\powershell_ise.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe")) and (not((ProcessCommandLine endswith " /s C:\\Windows\\System32\\RpcProxy\\RpcProxy.dll" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\cmd.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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