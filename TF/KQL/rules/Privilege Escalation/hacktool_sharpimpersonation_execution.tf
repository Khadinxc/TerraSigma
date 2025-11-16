resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_sharpimpersonation_execution" {
  name                       = "hacktool_sharpimpersonation_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SharpImpersonation Execution"
  description                = "Detects execution of the SharpImpersonation tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " user:" and ProcessCommandLine contains " binary:") or (ProcessCommandLine contains " user:" and ProcessCommandLine contains " shellcode:") or (ProcessCommandLine contains " technique:CreateProcessAsUserW" or ProcessCommandLine contains " technique:ImpersonateLoggedOnuser")) or (FolderPath endswith "\\SharpImpersonation.exe" or ProcessVersionInfoOriginalFileName =~ "SharpImpersonation.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1134"]
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