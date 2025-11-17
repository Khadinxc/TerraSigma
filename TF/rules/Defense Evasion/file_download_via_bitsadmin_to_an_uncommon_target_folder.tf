resource "azurerm_sentinel_alert_rule_scheduled" "file_download_via_bitsadmin_to_an_uncommon_target_folder" {
  name                       = "file_download_via_bitsadmin_to_an_uncommon_target_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Download Via Bitsadmin To An Uncommon Target Folder"
  description                = "Detects usage of bitsadmin downloading a file to uncommon target folder"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /transfer " or ProcessCommandLine contains " /create " or ProcessCommandLine contains " /addfile ") and (ProcessCommandLine contains "%AppData%" or ProcessCommandLine contains "%temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains "\\AppData\\Local\\" or ProcessCommandLine contains "C:\\Windows\\Temp\\") and (FolderPath endswith "\\bitsadmin.exe" or ProcessVersionInfoOriginalFileName =~ "bitsadmin.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
  techniques                 = ["T1197", "T1036"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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