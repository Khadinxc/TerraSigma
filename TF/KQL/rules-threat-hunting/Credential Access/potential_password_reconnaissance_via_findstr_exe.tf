resource "azurerm_sentinel_alert_rule_scheduled" "potential_password_reconnaissance_via_findstr_exe" {
  name                       = "potential_password_reconnaissance_via_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Password Reconnaissance Via Findstr.EXE"
  description                = "Detects command line usage of \"findstr\" to search for the \"passwords\" keyword in a variety of different languages"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "contraseña" or ProcessCommandLine contains "hasło" or ProcessCommandLine contains "heslo" or ProcessCommandLine contains "parola" or ProcessCommandLine contains "passe" or ProcessCommandLine contains "passw" or ProcessCommandLine contains "senha" or ProcessCommandLine contains "senord" or ProcessCommandLine contains "密碼") and (FolderPath endswith "\\findstr.exe" or ProcessVersionInfoOriginalFileName =~ "FINDSTR.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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