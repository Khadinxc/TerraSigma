resource "azurerm_sentinel_alert_rule_scheduled" "unc4841_download_compressed_files_from_temp_sh_using_wget" {
  name                       = "unc4841_download_compressed_files_from_temp_sh_using_wget"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UNC4841 - Download Compressed Files From Temp.sh Using Wget"
  description                = "Detects execution of \"wget\" to download a \".zip\" or \".rar\" files from \"temp.sh\". As seen used by UNC4841 during their Barracuda ESG zero day exploitation."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "https://temp.sh/" and (ProcessCommandLine endswith ".rar" or ProcessCommandLine endswith ".zip") and FolderPath endswith "/wget"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1140"]
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