resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_regsvr32_http_ftp_pattern" {
  name                       = "potentially_suspicious_regsvr32_http_ftp_pattern"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Regsvr32 HTTP/FTP Pattern"
  description                = "Detects regsvr32 execution to download/install/register new DLLs that are hosted on Web or FTP servers."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /i" or ProcessCommandLine contains " -i") and (FolderPath endswith "\\regsvr32.exe" or ProcessVersionInfoOriginalFileName =~ "REGSVR32.EXE") and (ProcessCommandLine contains "ftp" or ProcessCommandLine contains "http")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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