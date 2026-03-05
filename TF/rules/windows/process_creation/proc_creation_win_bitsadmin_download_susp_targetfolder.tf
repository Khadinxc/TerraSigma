resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_bitsadmin_download_susp_targetfolder" {
  name                       = "proc_creation_win_bitsadmin_download_susp_targetfolder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download Via Bitsadmin To A Suspicious Target Folder"
  description                = <<DESC
    Detects usage of bitsadmin downloading a file to a suspicious target folder

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_targetfolder.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /transfer " or ProcessCommandLine contains " /create " or ProcessCommandLine contains " /addfile ") and (ProcessCommandLine contains ":\\Perflogs" or ProcessCommandLine contains ":\\ProgramData\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\" or ProcessCommandLine contains "\\$Recycle.Bin\\" or ProcessCommandLine contains "\\AppData\\Local\\" or ProcessCommandLine contains "\\AppData\\Roaming\\" or ProcessCommandLine contains "\\Contacts\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Favorites\\" or ProcessCommandLine contains "\\Favourites\\" or ProcessCommandLine contains "\\inetpub\\wwwroot\\" or ProcessCommandLine contains "\\Music\\" or ProcessCommandLine contains "\\Pictures\\" or ProcessCommandLine contains "\\Start Menu\\Programs\\Startup\\" or ProcessCommandLine contains "\\Users\\Default\\" or ProcessCommandLine contains "\\Videos\\" or ProcessCommandLine contains "%ProgramData%" or ProcessCommandLine contains "%public%" or ProcessCommandLine contains "%temp%" or ProcessCommandLine contains "%tmp%") and (FolderPath endswith "\\bitsadmin.exe" or ProcessVersionInfoOriginalFileName =~ "bitsadmin.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "CommandAndControl"]
  techniques                 = ["T1197", "T1036", "T1105"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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