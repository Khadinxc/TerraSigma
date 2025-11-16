resource "azurerm_sentinel_alert_rule_scheduled" "file_download_via_curl_exe" {
  name                       = "file_download_via_curl_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download Via Curl.EXE"
  description                = "Detects file download using curl.exe - Scripts created by developers and admins - Administrative activity - The \"\\Git\\usr\\bin\\sh.exe\" process uses the \"--output\" flag to download a specific file in the temp directory with the pattern \"gfw-httpget-xxxxxxxx.txt \""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\curl.exe" or ProcessVersionInfoProductName =~ "The curl executable") and (ProcessCommandLine contains " -O" or ProcessCommandLine contains "--remote-name" or ProcessCommandLine contains "--output")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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