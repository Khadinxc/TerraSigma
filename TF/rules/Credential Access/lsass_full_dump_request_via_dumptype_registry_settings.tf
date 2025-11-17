resource "azurerm_sentinel_alert_rule_scheduled" "lsass_full_dump_request_via_dumptype_registry_settings" {
  name                       = "lsass_full_dump_request_via_dumptype_registry_settings"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Lsass Full Dump Request Via DumpType Registry Settings"
  description                = "Detects the setting of the \"DumpType\" registry value to \"2\" which stands for a \"Full Dump\". Technique such as LSASS Shtinkering requires this value to be \"2\" in order to dump LSASS. - Legitimate application that needs to do a full dump of their process"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000002)" and (RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType" or RegistryKey contains "\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\lsass.exe\\DumpType")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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