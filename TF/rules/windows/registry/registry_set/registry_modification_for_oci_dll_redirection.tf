resource "azurerm_sentinel_alert_rule_scheduled" "registry_modification_for_oci_dll_redirection" {
  name                       = "registry_modification_for_oci_dll_redirection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Modification for OCI DLL Redirection"
  description                = "Detects registry modifications related to 'OracleOciLib' and 'OracleOciLibPath' under 'MSDTC' settings. Threat actors may modify these registry keys to redirect the loading of 'oci.dll' to a malicious DLL, facilitating phantom DLL hijacking via the MSDTC service. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI\\OracleOciLib" and (not(RegistryValueData contains "oci.dll"))) or (RegistryKey endswith "\\SOFTWARE\\Microsoft\\MSDTC\\MTxOCI\\OracleOciLibPath" and (not(RegistryValueData contains "%SystemRoot%\\System32\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1112", "T1574"]
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