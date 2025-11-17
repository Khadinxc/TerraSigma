resource "azurerm_sentinel_alert_rule_scheduled" "potential_smadhook_dll_sideloading" {
  name                       = "potential_smadhook_dll_sideloading"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SmadHook.DLL Sideloading"
  description                = "Detects potential DLL sideloading of \"SmadHook.dll\", a DLL used by SmadAV antivirus - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\SmadHook32c.dll" or FolderPath endswith "\\SmadHook64c.dll") and (not(((InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\SMADAV\\SmadavProtect32.exe", "C:\\Program Files (x86)\\SMADAV\\SmadavProtect64.exe", "C:\\Program Files\\SMADAV\\SmadavProtect32.exe", "C:\\Program Files\\SMADAV\\SmadavProtect64.exe")) and (FolderPath startswith "C:\\Program Files (x86)\\SMADAV\\" or FolderPath startswith "C:\\Program Files\\SMADAV\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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