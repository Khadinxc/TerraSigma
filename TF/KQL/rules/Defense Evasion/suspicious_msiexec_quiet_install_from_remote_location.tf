resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_msiexec_quiet_install_from_remote_location" {
  name                       = "suspicious_msiexec_quiet_install_from_remote_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Msiexec Quiet Install From Remote Location"
  description                = "Detects usage of Msiexec.exe to install packages hosted remotely quietly"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-i" or ProcessCommandLine contains "/i" or ProcessCommandLine contains "–i" or ProcessCommandLine contains "—i" or ProcessCommandLine contains "―i" or ProcessCommandLine contains "-package" or ProcessCommandLine contains "/package" or ProcessCommandLine contains "–package" or ProcessCommandLine contains "—package" or ProcessCommandLine contains "―package" or ProcessCommandLine contains "-a" or ProcessCommandLine contains "/a" or ProcessCommandLine contains "–a" or ProcessCommandLine contains "—a" or ProcessCommandLine contains "―a" or ProcessCommandLine contains "-j" or ProcessCommandLine contains "/j" or ProcessCommandLine contains "–j" or ProcessCommandLine contains "—j" or ProcessCommandLine contains "―j") and (FolderPath endswith "\\msiexec.exe" or ProcessVersionInfoOriginalFileName =~ "msiexec.exe") and (ProcessCommandLine contains "-q" or ProcessCommandLine contains "/q" or ProcessCommandLine contains "–q" or ProcessCommandLine contains "—q" or ProcessCommandLine contains "―q") and (ProcessCommandLine contains "http" or ProcessCommandLine contains "\\\\")) and (not((ProcessCommandLine contains "\\AppData\\Local\\Temp\\OpenOffice" and ProcessCommandLine contains "Installation Files\\openoffice")))
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