resource "azurerm_sentinel_alert_rule_scheduled" "proxy_execution_via_wuauclt_exe" {
  name                       = "proxy_execution_via_wuauclt_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Proxy Execution Via Wuauclt.EXE"
  description                = "Detects the use of the Windows Update Client binary (wuauclt.exe) for proxy execution."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "UpdateDeploymentProvider" and ProcessCommandLine contains "RunHandlerComServer") and (FolderPath endswith "\\wuauclt.exe" or ProcessVersionInfoOriginalFileName =~ "wuauclt.exe")) and (not((ProcessCommandLine contains " /UpdateDeploymentProvider UpdateDeploymentProvider.dll " or (ProcessCommandLine contains ":\\Windows\\UUS\\Packages\\Preview\\amd64\\updatedeploy.dll /ClassId" or ProcessCommandLine contains ":\\Windows\\UUS\\amd64\\UpdateDeploy.dll /ClassId") or (ProcessCommandLine contains ":\\Windows\\WinSxS\\" and ProcessCommandLine contains "\\UpdateDeploy.dll /ClassId ") or ProcessCommandLine contains " wuaueng.dll ")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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