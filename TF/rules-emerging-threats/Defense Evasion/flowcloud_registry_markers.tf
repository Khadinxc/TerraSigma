resource "azurerm_sentinel_alert_rule_scheduled" "flowcloud_registry_markers" {
  name                       = "flowcloud_registry_markers"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "FlowCloud Registry Markers"
  description                = "Detects FlowCloud malware registry markers from threat group TA410. The malware stores its configuration in the registry alongside drivers utilized by the malware's keylogger components. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\HARDWARE\\{2DB80286-1784-48b5-A751-B6ED1F490303}" or RegistryKey contains "\\HARDWARE\\{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" or RegistryKey contains "\\HARDWARE\\{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" or RegistryKey endswith "\\SYSTEM\\Setup\\PrintResponsor*"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence"]
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
}