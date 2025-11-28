resource "azurerm_sentinel_alert_rule_scheduled" "oceanlotus_registry_activity" {
  name                       = "oceanlotus_registry_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "OceanLotus Registry Activity"
  description                = "Detects registry keys created in OceanLotus (also known as APT32) attacks"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\SOFTWARE\\Classes\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model" or (RegistryKey endswith "Classes\\AppXc52346ec40fb4061ad96be0e6cb7d16a*" or RegistryKey endswith "Classes\\AppX3bbba44c6cae4d9695755183472171e2*" or RegistryKey endswith "Classes\\CLSID\\{E3517E26-8E93-458D-A6DF-8030BC80528B}*" or RegistryKey contains "Classes\\CLSID\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\Model") or (RegistryKey endswith "\\SOFTWARE\\App*" and ((RegistryKey endswith "AppXbf13d4ea2945444d8b13e2121cb6b663*" or RegistryKey endswith "AppX70162486c7554f7f80f481985d67586d*" or RegistryKey endswith "AppX37cc7fdccd644b4f85f4b22d5a3f105a*") and (RegistryKey endswith "Application" or RegistryKey endswith "DefaultIcon")))
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
}