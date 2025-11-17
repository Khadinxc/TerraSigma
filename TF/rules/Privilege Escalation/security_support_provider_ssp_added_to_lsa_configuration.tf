resource "azurerm_sentinel_alert_rule_scheduled" "security_support_provider_ssp_added_to_lsa_configuration" {
  name                       = "security_support_provider_ssp_added_to_lsa_configuration"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Security Support Provider (SSP) Added to LSA Configuration"
  description                = "Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\Control\\Lsa\\Security Packages" or RegistryKey endswith "\\Control\\Lsa\\OSConfig\\Security Packages") and (not((InitiatingProcessFolderPath in~ ("C:\\Windows\\system32\\msiexec.exe", "C:\\Windows\\syswow64\\MsiExec.exe"))))
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