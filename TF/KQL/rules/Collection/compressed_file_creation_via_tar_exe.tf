resource "azurerm_sentinel_alert_rule_scheduled" "compressed_file_creation_via_tar_exe" {
  name                       = "compressed_file_creation_via_tar_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Compressed File Creation Via Tar.EXE"
  description                = "Detects execution of \"tar.exe\" in order to create a compressed file. Adversaries may abuse various utilities to compress or encrypt data before exfiltration. - Likely"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-c" or ProcessCommandLine contains "-r" or ProcessCommandLine contains "-u") and (FolderPath endswith "\\tar.exe" or ProcessVersionInfoOriginalFileName =~ "bsdtar")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "Exfiltration"]
  techniques                 = ["T1560"]
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