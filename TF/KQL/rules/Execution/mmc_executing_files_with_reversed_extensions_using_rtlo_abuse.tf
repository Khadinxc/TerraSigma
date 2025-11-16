resource "azurerm_sentinel_alert_rule_scheduled" "mmc_executing_files_with_reversed_extensions_using_rtlo_abuse" {
  name                       = "mmc_executing_files_with_reversed_extensions_using_rtlo_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "MMC Executing Files with Reversed Extensions Using RTLO Abuse"
  description                = "Detects malicious behavior where the MMC utility (`mmc.exe`) executes files with reversed extensions caused by Right-to-Left Override (RLO) abuse, disguising them as document formats. - Legitimate administrative actions using MMC to execute misnamed `.msc` files. - Unconventional but non-malicious usage of RLO or reversed extensions."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "cod.msc" or ProcessCommandLine contains "fdp.msc" or ProcessCommandLine contains "ftr.msc" or ProcessCommandLine contains "lmth.msc" or ProcessCommandLine contains "slx.msc" or ProcessCommandLine contains "tdo.msc" or ProcessCommandLine contains "xcod.msc" or ProcessCommandLine contains "xslx.msc" or ProcessCommandLine contains "xtpp.msc") and (FolderPath endswith "\\mmc.exe" or ProcessVersionInfoOriginalFileName =~ "MMC.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1204", "T1218", "T1036"]
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