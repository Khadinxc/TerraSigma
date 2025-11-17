resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_child_process_of_manage_engine_servicedesk" {
  name                       = "suspicious_child_process_of_manage_engine_servicedesk"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process Of Manage Engine ServiceDesk"
  description                = "Detects suspicious child processes of the \"Manage Engine ServiceDesk Plus\" Java web service - Legitimate sub processes started by Manage Engine ServiceDesk Pro"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\AppVLP.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\calc.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\curl.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\mftrace.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe" or FolderPath endswith "\\notepad.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\query.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\scrcons.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\systeminfo.exe" or FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe") and (InitiatingProcessFolderPath contains "\\ManageEngine\\ServiceDesk\\" and InitiatingProcessFolderPath contains "\\java.exe")) and (not((ProcessCommandLine contains " stop" and (FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1102"]
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