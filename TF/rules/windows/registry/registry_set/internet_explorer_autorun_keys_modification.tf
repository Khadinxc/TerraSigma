resource "azurerm_sentinel_alert_rule_scheduled" "internet_explorer_autorun_keys_modification" {
  name                       = "internet_explorer_autorun_keys_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Internet Explorer Autorun Keys Modification"
  description                = "Detects modification of autostart extensibility point (ASEP) in registry. - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason - Legitimate administrator sets up autorun keys for legitimate reason"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Software\\Wow6432Node\\Microsoft\\Internet Explorer" or RegistryKey contains "\\Software\\Microsoft\\Internet Explorer") and (RegistryKey contains "\\Toolbar" or RegistryKey contains "\\Extensions" or RegistryKey contains "\\Explorer Bars") and (not((RegistryValueData =~ "(Empty)" or (RegistryKey contains "\\Extensions\\{2670000A-7350-4f3c-8081-5663EE0C6C49}" or RegistryKey contains "\\Extensions\\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" or RegistryKey contains "\\Extensions\\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" or RegistryKey contains "\\Extensions\\{A95fe080-8f5d-11d2-a20b-00aa003c157a}") or (RegistryKey endswith "\\Toolbar\\ShellBrowser\\ITBar7Layout" or RegistryKey endswith "\\Toolbar\\ShowDiscussionButton" or RegistryKey endswith "\\Toolbar\\Locked"))))
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