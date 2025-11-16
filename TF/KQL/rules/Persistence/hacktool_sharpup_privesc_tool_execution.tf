resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_sharpup_privesc_tool_execution" {
  name                       = "hacktool_sharpup_privesc_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SharpUp PrivEsc Tool Execution"
  description                = "Detects the use of SharpUp, a tool for local privilege escalation"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\SharpUp.exe" or ProcessVersionInfoFileDescription =~ "SharpUp" or (ProcessCommandLine contains "HijackablePaths" or ProcessCommandLine contains "UnquotedServicePath" or ProcessCommandLine contains "ProcessDLLHijack" or ProcessCommandLine contains "ModifiableServiceBinaries" or ProcessCommandLine contains "ModifiableScheduledTask" or ProcessCommandLine contains "DomainGPPPassword" or ProcessCommandLine contains "CachedGPPPassword")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation", "Discovery", "Execution"]
  techniques                 = ["T1615", "T1569", "T1574"]
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