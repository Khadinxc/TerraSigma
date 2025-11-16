resource "azurerm_sentinel_alert_rule_scheduled" "potential_configuration_and_service_reconnaissance_via_reg_exe" {
  name                       = "potential_configuration_and_service_reconnaissance_via_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Configuration And Service Reconnaissance Via Reg.EXE"
  description                = "Detects the usage of \"reg.exe\" in order to query reconnaissance information from the registry. Adversaries may interact with the Windows registry to gather information about credentials, the system, configuration, and installed software. - Discord"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "query" and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe") and (ProcessCommandLine contains "currentVersion\\windows" or ProcessCommandLine contains "winlogon\\" or ProcessCommandLine contains "currentVersion\\shellServiceObjectDelayLoad" or ProcessCommandLine contains "currentVersion\\run" or ProcessCommandLine contains "currentVersion\\policies\\explorer\\run" or ProcessCommandLine contains "currentcontrolset\\services")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1012", "T1007"]
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