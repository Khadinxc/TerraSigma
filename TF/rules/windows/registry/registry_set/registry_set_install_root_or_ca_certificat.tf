resource "azurerm_sentinel_alert_rule_scheduled" "registry_set_install_root_or_ca_certificat" {
  name                       = "registry_set_install_root_or_ca_certificat"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Root or CA or AuthRoot Certificate to Store"
  description                = <<DESC
    Detects the addition of new root, CA or AuthRoot certificates to the Windows registry

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_install_root_or_ca_certificat.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "Binary Data" and (RegistryKey endswith "\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Microsoft\\SystemCertificates\\CA\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\CA\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\CA\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\AuthRoot\\Certificates*" or RegistryKey endswith "\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\AuthRoot\\Certificates*") and RegistryKey endswith "\\Blob"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}