resource "azurerm_sentinel_alert_rule_scheduled" "use_of_the_sftp_exe_binary_as_a_lolbin" {
  name                       = "use_of_the_sftp_exe_binary_as_a_lolbin"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Use Of The SFTP.EXE Binary As A LOLBIN"
  description                = "Detects the usage of the \"sftp.exe\" binary as a LOLBIN by abusing the \"-D\" flag"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -D .." or ProcessCommandLine contains " -D C:\\") and FolderPath endswith "\\sftp.exe"
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