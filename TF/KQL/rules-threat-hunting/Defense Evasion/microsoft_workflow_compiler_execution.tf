resource "azurerm_sentinel_alert_rule_scheduled" "microsoft_workflow_compiler_execution" {
  name                       = "microsoft_workflow_compiler_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft Workflow Compiler Execution"
  description                = "Detects the execution of Microsoft Workflow Compiler, which may permit the execution of arbitrary unsigned code. - Legitimate MWC use (unlikely in modern enterprise environments)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\Microsoft.Workflow.Compiler.exe" or ProcessVersionInfoOriginalFileName =~ "Microsoft.Workflow.Compiler.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1127", "T1218"]
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