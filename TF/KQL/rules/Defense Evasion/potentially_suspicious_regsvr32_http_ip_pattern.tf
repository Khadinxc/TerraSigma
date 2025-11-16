resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_regsvr32_http_ip_pattern" {
  name                       = "potentially_suspicious_regsvr32_http_ip_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Regsvr32 HTTP IP Pattern"
  description                = "Detects regsvr32 execution to download and install DLLs located remotely where the address is an IP address. - FQDNs that start with a number such as \"7-Zip\""
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\regsvr32.exe" or ProcessVersionInfoOriginalFileName =~ "REGSVR32.EXE") and (ProcessCommandLine contains " /i:http://1" or ProcessCommandLine contains " /i:http://2" or ProcessCommandLine contains " /i:http://3" or ProcessCommandLine contains " /i:http://4" or ProcessCommandLine contains " /i:http://5" or ProcessCommandLine contains " /i:http://6" or ProcessCommandLine contains " /i:http://7" or ProcessCommandLine contains " /i:http://8" or ProcessCommandLine contains " /i:http://9" or ProcessCommandLine contains " /i:https://1" or ProcessCommandLine contains " /i:https://2" or ProcessCommandLine contains " /i:https://3" or ProcessCommandLine contains " /i:https://4" or ProcessCommandLine contains " /i:https://5" or ProcessCommandLine contains " /i:https://6" or ProcessCommandLine contains " /i:https://7" or ProcessCommandLine contains " /i:https://8" or ProcessCommandLine contains " /i:https://9" or ProcessCommandLine contains " -i:http://1" or ProcessCommandLine contains " -i:http://2" or ProcessCommandLine contains " -i:http://3" or ProcessCommandLine contains " -i:http://4" or ProcessCommandLine contains " -i:http://5" or ProcessCommandLine contains " -i:http://6" or ProcessCommandLine contains " -i:http://7" or ProcessCommandLine contains " -i:http://8" or ProcessCommandLine contains " -i:http://9" or ProcessCommandLine contains " -i:https://1" or ProcessCommandLine contains " -i:https://2" or ProcessCommandLine contains " -i:https://3" or ProcessCommandLine contains " -i:https://4" or ProcessCommandLine contains " -i:https://5" or ProcessCommandLine contains " -i:https://6" or ProcessCommandLine contains " -i:https://7" or ProcessCommandLine contains " -i:https://8" or ProcessCommandLine contains " -i:https://9")
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}