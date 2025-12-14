resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_loading_of_dbgcore_dbghelp_dlls_from_uncommon_location" {
  name                       = "suspicious_loading_of_dbgcore_dbghelp_dlls_from_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location"
  description                = "Detects loading of dbgcore.dll or dbghelp.dll from uncommon locations such as user directories. These DLLs contain the MiniDumpWriteDump function, which can be abused for credential dumping purposes or in some cases for evading EDR/AV detection by suspending processes. - Possibly during software installation or update processes"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\dbgcore.dll" or FolderPath endswith "\\dbghelp.dll") and (InitiatingProcessFolderPath contains ":\\Perflogs\\" or InitiatingProcessFolderPath contains ":\\Temp\\" or InitiatingProcessFolderPath contains ":\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\$Recycle.Bin\\" or InitiatingProcessFolderPath contains "\\Contacts\\" or InitiatingProcessFolderPath contains "\\Desktop\\" or InitiatingProcessFolderPath contains "\\Documents\\" or InitiatingProcessFolderPath contains "\\Downloads\\" or InitiatingProcessFolderPath contains "\\Favorites\\" or InitiatingProcessFolderPath contains "\\Favourites\\" or InitiatingProcessFolderPath contains "\\inetpub\\wwwroot\\" or InitiatingProcessFolderPath contains "\\Music\\" or InitiatingProcessFolderPath contains "\\Pictures\\" or InitiatingProcessFolderPath contains "\\Start Menu\\Programs\\Startup\\" or InitiatingProcessFolderPath contains "\\Users\\Default\\" or InitiatingProcessFolderPath contains "\\Videos\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "DefenseEvasion"]
  techniques                 = ["T1003", "T1562"]
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