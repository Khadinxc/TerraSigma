resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_microsoft_office_trusted_location_added" {
  name                       = "uncommon_microsoft_office_trusted_location_added"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Microsoft Office Trusted Location Added"
  description                = "Detects changes to registry keys related to \"Trusted Location\" of Microsoft Office where the path is set to something uncommon. Attackers might add additional trusted locations to avoid macro security restrictions. - Other unknown legitimate or custom paths need to be filtered to avoid false positives"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "Security\\Trusted Locations\\Location" and RegistryKey endswith "\\Path") and (not(((InitiatingProcessFolderPath contains ":\\Program Files\\Microsoft Office\\" or InitiatingProcessFolderPath contains ":\\Program Files (x86)\\Microsoft Office\\") or (InitiatingProcessFolderPath contains ":\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\" and InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe")))) and (not((RegistryValueData contains "%APPDATA%\\Microsoft\\Templates" or RegistryValueData contains "%%APPDATA%%\\Microsoft\\Templates" or RegistryValueData contains "%APPDATA%\\Microsoft\\Word\\Startup" or RegistryValueData contains "%%APPDATA%%\\Microsoft\\Word\\Startup" or RegistryValueData contains ":\\Program Files (x86)\\Microsoft Office\\root\\Templates\\" or RegistryValueData contains ":\\Program Files\\Microsoft Office (x86)\\Templates" or RegistryValueData contains ":\\Program Files\\Microsoft Office\\root\\Templates\\" or RegistryValueData contains ":\\Program Files\\Microsoft Office\\Templates\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}