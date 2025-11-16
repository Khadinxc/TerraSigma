resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_rundll32_execution_with_image_extension" {
  name                       = "suspicious_rundll32_execution_with_image_extension"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Rundll32 Execution With Image Extension"
  description                = "Detects the execution of Rundll32.exe with DLL files masquerading as image files"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".bmp" or ProcessCommandLine contains ".cr2" or ProcessCommandLine contains ".eps" or ProcessCommandLine contains ".gif" or ProcessCommandLine contains ".ico" or ProcessCommandLine contains ".jpeg" or ProcessCommandLine contains ".jpg" or ProcessCommandLine contains ".nef" or ProcessCommandLine contains ".orf" or ProcessCommandLine contains ".png" or ProcessCommandLine contains ".raw" or ProcessCommandLine contains ".sr2" or ProcessCommandLine contains ".tif" or ProcessCommandLine contains ".tiff") and (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.exe")
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