resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_new_amsi_providers_registry" {
  name                       = "potential_persistence_via_new_amsi_providers_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via New AMSI Providers - Registry"
  description                = "Detects when an attacker adds a new AMSI provider via the Windows Registry to bypass AMSI (Antimalware Scan Interface) protections. Attackers may add custom AMSI providers to persist on the system and evade detection by security software that relies on AMSI for scanning scripts and other content. This technique is often used in conjunction with fileless malware and script-based attacks to maintain persistence while avoiding detection. - Legitimate security products adding their own AMSI providers. Filter these according to your environment."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\SOFTWARE\\Microsoft\\AMSI\\Providers*" or RegistryKey endswith "\\SOFTWARE\\WOW6432Node\\Microsoft\\AMSI\\Providers*") and (not((((InitiatingProcessFolderPath in~ ("C:\\Program Files\\Avast Software\\Avast\\RegSvr.exe", "C:\\Program Files\\Avast Software\\Avast\\x86\\RegSvr.exe")) and RegistryKey contains "\\{FB904E4E-D2C7-4C8D-8492-B620BB9896B1}") or ((InitiatingProcessFolderPath in~ ("C:\\Program Files\\AVG\\Antivirus\\RegSvr.exe", "C:\\Program Files\\AVG\\Antivirus\\x86\\RegSvr.exe")) and RegistryKey contains "\\{FB904E4E-D2C7-4C8D-8492-B620BB9896B1}") or (InitiatingProcessFolderPath =~ "C:\\Program Files\\Avira\\Endpoint Protection SDK\\endpointprotection.exe" and RegistryKey contains "\\{00000001-3DCC-4B48-A82E-E2071FE58E05}"))))
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}