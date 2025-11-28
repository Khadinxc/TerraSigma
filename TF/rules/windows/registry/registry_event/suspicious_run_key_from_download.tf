resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_run_key_from_download" {
  name                       = "suspicious_run_key_from_download"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Run Key from Download"
  description                = "Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories - Software installers downloaded and used by users"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (InitiatingProcessFolderPath contains "\\AppData\\Local\\Packages\\Microsoft.Outlook_" or InitiatingProcessFolderPath contains "\\AppData\\Local\\Microsoft\\Olk\\Attachments\\" or InitiatingProcessFolderPath contains "\\Downloads\\" or InitiatingProcessFolderPath contains "\\Temporary Internet Files\\Content.Outlook\\" or InitiatingProcessFolderPath contains "\\Local Settings\\Temporary Internet Files\\") and (RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" or RegistryKey contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or RegistryKey contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}