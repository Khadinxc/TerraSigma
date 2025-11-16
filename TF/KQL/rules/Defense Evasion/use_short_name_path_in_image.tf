resource "azurerm_sentinel_alert_rule_scheduled" "use_short_name_path_in_image" {
  name                       = "use_short_name_path_in_image"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Use Short Name Path in Image"
  description                = "Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image detection - Applications could use this notation occasionally which might generate some false positives. In that case Investigate the parent and child process."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "~1\\" or FolderPath contains "~2\\") and (not((((FolderPath contains "\\AppData\\" and FolderPath contains "\\Temp\\") or (FolderPath endswith "~1\\unzip.exe" or FolderPath endswith "~1\\7zG.exe")) or (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\Dism.exe", "C:\\Windows\\System32\\cleanmgr.exe"))))) and (not(((ProcessVersionInfoProductName =~ "InstallShield (R)" or ProcessVersionInfoFileDescription =~ "InstallShield (R) Setup Engine" or ProcessVersionInfoCompanyName =~ "InstallShield Software Corporation") or InitiatingProcessFolderPath endswith "\\thor\\thor64.exe" or InitiatingProcessFolderPath endswith "\\WebEx\\WebexHost.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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