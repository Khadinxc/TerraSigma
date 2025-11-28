resource "azurerm_sentinel_alert_rule_scheduled" "directory_service_restore_mode_dsrm_registry_value_tampering" {
  name                       = "directory_service_restore_mode_dsrm_registry_value_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Directory Service Restore Mode(DSRM) Registry Value Tampering"
  description                = "Detects changes to \"DsrmAdminLogonBehavior\" registry value. During a Domain Controller (DC) promotion, administrators create a Directory Services Restore Mode (DSRM) local administrator account with a password that rarely changes. The DSRM account is an “Administrator” account that logs in with the DSRM mode when the server is booting up to restore AD backups or recover the server from a failure. Attackers could abuse DSRM account to maintain their persistence and access to the organization's Active Directory. If the \"DsrmAdminLogonBehavior\" value is set to \"0\", the administrator account can only be used if the DC starts in DSRM. If the \"DsrmAdminLogonBehavior\" value is set to \"1\", the administrator account can only be used if the local AD DS service is stopped. If the \"DsrmAdminLogonBehavior\" value is set to \"2\", the administrator account can always be used."
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "\\Control\\Lsa\\DsrmAdminLogonBehavior" and (not(RegistryValueData =~ "DWORD (0x00000000)"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess", "Persistence"]
  techniques                 = ["T1556"]
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