resource "azurerm_sentinel_alert_rule_scheduled" "vbscript_payload_stored_in_registry" {
  name                       = "vbscript_payload_stored_in_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "VBScript Payload Stored in Registry"
  description                = "Detects VBScript content stored into registry keys as seen being used by UNC2452 group"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData contains "vbscript:" or RegistryValueData contains "jscript:" or RegistryValueData contains "mshtml," or RegistryValueData contains "RunHTMLApplication" or RegistryValueData contains "Execute(" or RegistryValueData contains "CreateObject" or RegistryValueData contains "window.close") and RegistryKey contains "Software\\Microsoft\\Windows\\CurrentVersion") and (not((RegistryKey contains "Software\\Microsoft\\Windows\\CurrentVersion\\Run" or ((RegistryValueData contains "\\Microsoft.NET\\Primary Interop Assemblies\\Microsoft.mshtml.dll" or RegistryValueData contains "<\\Microsoft.mshtml,fileVersion=" or RegistryValueData contains "_mshtml_dll_" or RegistryValueData contains "<\\Microsoft.mshtml,culture=") and InitiatingProcessFolderPath endswith "\\msiexec.exe" and RegistryKey endswith "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData*"))))
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

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}