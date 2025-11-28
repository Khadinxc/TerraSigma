resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_event_viewer_events_asp" {
  name                       = "potential_persistence_via_event_viewer_events_asp"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Event Viewer Events.asp"
  description                = "Detects potential registry persistence technique using the Event Viewer \"Events.asp\" technique"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey contains "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgram" or RegistryKey contains "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionURL") and (not((RegistryValueData =~ "(Empty)" or (RegistryValueData =~ "%%SystemRoot%%\\PCHealth\\HelpCtr\\Binaries\\HelpCtr.exe" and InitiatingProcessFolderPath endswith "C:\\WINDOWS\\system32\\svchost.exe" and RegistryKey endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgram") or (RegistryValueData =~ "-url hcp://services/centers/support*topic=%%s" and InitiatingProcessFolderPath endswith "C:\\WINDOWS\\system32\\svchost.exe" and RegistryKey endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Event Viewer\\MicrosoftRedirectionProgramCommandLineParameters") or RegistryValueData =~ "http://go.microsoft.com/fwlink/events.asp")))
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

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}