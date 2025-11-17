resource "azurerm_sentinel_alert_rule_scheduled" "files_with_system_dll_name_in_unsuspected_locations" {
  name                       = "files_with_system_dll_name_in_unsuspected_locations"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Files With System DLL Name In Unsuspected Locations"
  description                = "Detects the creation of a file with the \".dll\" extension that has the name of a System DLL in uncommon or unsuspected locations. (Outisde of \"System32\", \"SysWOW64\", etc.). It is highly recommended to perform an initial baseline before using this rule in production. - Third party software might bundle specific versions of system DLLs."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\secur32.dll" or FolderPath endswith "\\tdh.dll") and (not((FolderPath contains "C:\\$WINDOWS.~BT\\" or FolderPath contains "C:\\$WinREAgent\\" or FolderPath contains "C:\\Windows\\SoftwareDistribution\\" or FolderPath contains "C:\\Windows\\System32\\" or FolderPath contains "C:\\Windows\\SysWOW64\\" or FolderPath contains "C:\\Windows\\WinSxS\\" or FolderPath contains "C:\\Windows\\uus\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}