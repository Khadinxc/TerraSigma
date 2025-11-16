resource "azurerm_sentinel_alert_rule_scheduled" "new_generic_credentials_added_via_cmdkey_exe" {
  name                       = "new_generic_credentials_added_via_cmdkey_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Generic Credentials Added Via Cmdkey.EXE"
  description                = "Detects usage of \"cmdkey.exe\" to add generic credentials. As an example, this can be used before connecting to an RDP session via command line interface. - Legitimate usage for administration purposes"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -g" or ProcessCommandLine contains " /g" or ProcessCommandLine contains " –g" or ProcessCommandLine contains " —g" or ProcessCommandLine contains " ―g") and (ProcessCommandLine contains " -p" or ProcessCommandLine contains " /p" or ProcessCommandLine contains " –p" or ProcessCommandLine contains " —p" or ProcessCommandLine contains " ―p") and (ProcessCommandLine contains " -u" or ProcessCommandLine contains " /u" or ProcessCommandLine contains " –u" or ProcessCommandLine contains " —u" or ProcessCommandLine contains " ―u") and (FolderPath endswith "\\cmdkey.exe" or ProcessVersionInfoOriginalFileName =~ "cmdkey.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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