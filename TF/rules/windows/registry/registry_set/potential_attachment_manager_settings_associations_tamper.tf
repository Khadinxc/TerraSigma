resource "azurerm_sentinel_alert_rule_scheduled" "potential_attachment_manager_settings_associations_tamper" {
  name                       = "potential_attachment_manager_settings_associations_tamper"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Attachment Manager Settings Associations Tamper"
  description                = "Detects tampering with attachment manager settings policies associations to lower the default file type risks (See reference for more information) - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations*" and ((RegistryValueData =~ "DWORD (0x00006152)" and RegistryKey endswith "\\DefaultFileTypeRisk") or ((RegistryValueData contains ".zip;" or RegistryValueData contains ".rar;" or RegistryValueData contains ".exe;" or RegistryValueData contains ".bat;" or RegistryValueData contains ".com;" or RegistryValueData contains ".cmd;" or RegistryValueData contains ".reg;" or RegistryValueData contains ".msi;" or RegistryValueData contains ".htm;" or RegistryValueData contains ".html;") and RegistryKey endswith "\\LowRiskFileTypes"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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