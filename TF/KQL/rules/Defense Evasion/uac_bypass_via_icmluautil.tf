resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_via_icmluautil" {
  name                       = "uac_bypass_via_icmluautil"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass via ICMLuaUtil"
  description                = "Detects the pattern of UAC Bypass using ICMLuaUtil Elevated COM interface"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((InitiatingProcessCommandLine contains "/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" or InitiatingProcessCommandLine contains "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") and InitiatingProcessFolderPath endswith "\\dllhost.exe") and (not((FolderPath endswith "\\WerFault.exe" or ProcessVersionInfoOriginalFileName =~ "WerFault.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
      identifier  = "ProcessId"
      column_name = "ProcessId"
    }
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