resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_sharpmove_tool_execution" {
  name                       = "hacktool_sharpmove_tool_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SharpMove Tool Execution"
  description                = "Detects the execution of SharpMove, a .NET utility performing multiple tasks such as \"Task Creation\", \"SCM\" query, VBScript execution using WMI via its PE metadata and command line options."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\SharpMove.exe" or ProcessVersionInfoOriginalFileName =~ "SharpMove.exe") or ((ProcessCommandLine contains "action=create" or ProcessCommandLine contains "action=dcom" or ProcessCommandLine contains "action=executevbs" or ProcessCommandLine contains "action=hijackdcom" or ProcessCommandLine contains "action=modschtask" or ProcessCommandLine contains "action=modsvc" or ProcessCommandLine contains "action=query" or ProcessCommandLine contains "action=scm" or ProcessCommandLine contains "action=startservice" or ProcessCommandLine contains "action=taskscheduler") and ProcessCommandLine contains "computername=")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1021"]
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