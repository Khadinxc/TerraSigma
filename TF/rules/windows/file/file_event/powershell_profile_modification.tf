resource "azurerm_sentinel_alert_rule_scheduled" "powershell_profile_modification" {
  name                       = "powershell_profile_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Profile Modification"
  description                = "Detects the creation or modification of a powershell profile which could indicate suspicious activity as the profile can be used as a mean of persistence - System administrator creating Powershell profile manually"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\Microsoft.PowerShell_profile.ps1" or FolderPath endswith "\\PowerShell\\profile.ps1" or FolderPath endswith "\\Program Files\\PowerShell\\7-preview\\profile.ps1" or FolderPath endswith "\\Program Files\\PowerShell\\7\\profile.ps1" or FolderPath endswith "\\Windows\\System32\\WindowsPowerShell\\v1.0\\profile.ps1" or FolderPath endswith "\\WindowsPowerShell\\profile.ps1"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1546"]
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