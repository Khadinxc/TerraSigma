resource "azurerm_sentinel_alert_rule_scheduled" "registry_delete_removal_amsi_registry_key" {
  name                       = "registry_delete_removal_amsi_registry_key"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Removal Of AMSI Provider Registry Keys"
  description                = "Detects the deletion of AMSI provider registry key entries in HKLM\\Software\\Microsoft\\AMSI. This technique could be used by an attacker in order to disable AMSI inspection. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "{2781761E-28E0-4109-99FE-B9D127C57AFE}" or RegistryKey endswith "{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}") and (not((InitiatingProcessFolderPath endswith "\\MsMpEng.exe" and (InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Windows Defender\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Windows Defender\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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