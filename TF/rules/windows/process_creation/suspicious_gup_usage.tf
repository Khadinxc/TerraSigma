resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_gup_usage" {
  name                       = "suspicious_gup_usage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious GUP Usage"
  description                = "Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks - Execution of tools named GUP.exe and located in folders different than Notepad++\\updater"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\GUP.exe" and (not(((FolderPath endswith "\\Program Files\\Notepad++\\updater\\GUP.exe" or FolderPath endswith "\\Program Files (x86)\\Notepad++\\updater\\GUP.exe") or (FolderPath contains "\\Users\\" and (FolderPath endswith "\\AppData\\Local\\Notepad++\\updater\\GUP.exe" or FolderPath endswith "\\AppData\\Roaming\\Notepad++\\updater\\GUP.exe")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
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