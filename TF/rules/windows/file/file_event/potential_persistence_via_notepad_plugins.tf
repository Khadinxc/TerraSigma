resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_notepad_plugins" {
  name                       = "potential_persistence_via_notepad_plugins"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Notepad++ Plugins"
  description                = "Detects creation of new \".dll\" files inside the plugins directory of a notepad++ installation by a process other than \"gup.exe\". Which could indicates possible persistence - Possible FPs during first installation of Notepad++ - Legitimate use of custom plugins by users in order to enhance notepad++ functionalities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\Notepad++\\plugins\\" and FolderPath endswith ".dll") and (not((InitiatingProcessFolderPath endswith "\\Notepad++\\updater\\gup.exe" or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" and (InitiatingProcessFolderPath endswith "\\target.exe" or InitiatingProcessFolderPath endswith "Installer.x64.exe") and InitiatingProcessFolderPath startswith "C:\\Users\\") or (InitiatingProcessFolderPath contains "\\npp." and InitiatingProcessFolderPath endswith ".exe" and (FolderPath in~ ("C:\\Program Files\\Notepad++\\plugins\\NppExport\\NppExport.dll", "C:\\Program Files\\Notepad++\\plugins\\mimeTools\\mimeTools.dll", "C:\\Program Files\\Notepad++\\plugins\\NppConverter\\NppConverter.dll", "C:\\Program Files\\Notepad++\\plugins\\Config\\nppPluginList.dll"))))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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