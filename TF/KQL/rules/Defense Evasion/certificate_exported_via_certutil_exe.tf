resource "azurerm_sentinel_alert_rule_scheduled" "certificate_exported_via_certutil_exe" {
  name                       = "certificate_exported_via_certutil_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Certificate Exported Via Certutil.EXE"
  description                = "Detects the execution of the certutil with the \"exportPFX\" flag which allows the utility to export certificates. - There legitimate reasons to export certificates. Investigate the activity to determine if it's benign"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-exportPFX " or ProcessCommandLine contains "/exportPFX " or ProcessCommandLine contains "–exportPFX " or ProcessCommandLine contains "—exportPFX " or ProcessCommandLine contains "―exportPFX ") and (FolderPath endswith "\\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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