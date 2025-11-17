resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_autorun_registry_modified_via_wmi" {
  name                       = "suspicious_autorun_registry_modified_via_wmi"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Autorun Registry Modified via WMI"
  description                = "Detects suspicious activity where the WMIC process is used to create an autorun registry entry via reg.exe, which is often indicative of persistence mechanisms employed by malware. - Legitimate administrative activity or software installations"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" or ProcessCommandLine contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or ProcessCommandLine contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") and (ProcessCommandLine contains "reg" and ProcessCommandLine contains " add ")) and (FolderPath endswith "\\wmic.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe" or InitiatingProcessFolderPath endswith "\\wmiprvse.exe")) and ((ProcessCommandLine contains ":\\Perflogs" or ProcessCommandLine contains ":\\ProgramData'" or ProcessCommandLine contains ":\\Windows\\Temp" or ProcessCommandLine contains ":\\Temp" or ProcessCommandLine contains "\\AppData\\Local\\Temp" or ProcessCommandLine contains "\\AppData\\Roaming" or ProcessCommandLine contains ":\\$Recycle.bin" or ProcessCommandLine contains ":\\Users\\Default" or ProcessCommandLine contains ":\\Users\\public" or ProcessCommandLine contains "%temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains "%Public%" or ProcessCommandLine contains "%AppData%") or (ProcessCommandLine contains ":\\Users\\" and (ProcessCommandLine contains "\\Favorites" or ProcessCommandLine contains "\\Favourites" or ProcessCommandLine contains "\\Contacts" or ProcessCommandLine contains "\\Music" or ProcessCommandLine contains "\\Pictures" or ProcessCommandLine contains "\\Documents" or ProcessCommandLine contains "\\Photos")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1547", "T1047"]
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