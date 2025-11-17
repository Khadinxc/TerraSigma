resource "azurerm_sentinel_alert_rule_scheduled" "kapeka_backdoor_loaded_via_rundll32_exe" {
  name                       = "kapeka_backdoor_loaded_via_rundll32_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Kapeka Backdoor Loaded Via Rundll32.EXE"
  description                = "Detects the Kapeka Backdoor binary being loaded by rundll32.exe. The Kapeka loader drops a backdoor, which is a DLL with the '.wll' extension masquerading as a Microsoft Word Add-In."
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath contains ":\\ProgramData" or FolderPath contains "\\AppData\\Local\\") and FolderPath matches regex "[a-zA-Z]{5,6}\\.wll" and InitiatingProcessFolderPath endswith "\\rundll32.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1204", "T1218"]
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