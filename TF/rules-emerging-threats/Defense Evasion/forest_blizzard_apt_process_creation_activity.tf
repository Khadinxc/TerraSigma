resource "azurerm_sentinel_alert_rule_scheduled" "forest_blizzard_apt_process_creation_activity" {
  name                       = "forest_blizzard_apt_process_creation_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Forest Blizzard APT - Process Creation Activity"
  description                = "Detects the execution of specific processes and command line combination. These were seen being created by Forest Blizzard as described by MSFT."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (SHA256 startswith "6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f" or SHA256 startswith "c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5") or (ProcessCommandLine contains "Get-ChildItem" and ProcessCommandLine contains ".save" and ProcessCommandLine contains "Compress-Archive -DestinationPath C:\\ProgramData\\") or ((ProcessCommandLine contains "servtask.bat" or ProcessCommandLine contains "execute.bat" or ProcessCommandLine contains "doit.bat") and (ProcessCommandLine contains "Create" and ProcessCommandLine contains "/RU" and ProcessCommandLine contains "SYSTEM" and ProcessCommandLine contains "\\Microsoft\\Windows\\WinSrv") and FolderPath endswith "\\schtasks.exe") or ((ProcessCommandLine contains "Delete" and ProcessCommandLine contains "/F " and ProcessCommandLine contains "\\Microsoft\\Windows\\WinSrv") and FolderPath endswith "\\schtasks.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}