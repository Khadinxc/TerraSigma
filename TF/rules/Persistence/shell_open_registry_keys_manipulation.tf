resource "azurerm_sentinel_alert_rule_scheduled" "shell_open_registry_keys_manipulation" {
  name                       = "shell_open_registry_keys_manipulation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell Open Registry Keys Manipulation"
  description                = "Detects the shell open key manipulation (exefile and ms-settings) used for persistence and the pattern of UAC Bypass using fodhelper.exe, computerdefaults.exe, slui.exe via registry keys (e.g. UACMe 33 or 62)"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryValueData contains "\\Software\\Classes\\{" and ActionType =~ "RegistryValueSet" and RegistryKey endswith "Classes\\ms-settings\\shell\\open\\command\\SymbolicLinkValue") or RegistryKey endswith "Classes\\ms-settings\\shell\\open\\command\\DelegateExecute" or ((ActionType =~ "RegistryValueSet" and (RegistryKey endswith "Classes\\ms-settings\\shell\\open\\command\\(Default)" or RegistryKey endswith "Classes\\exefile\\shell\\open\\command\\(Default)")) and (not(RegistryValueData =~ "(Empty)")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548", "T1546"]
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