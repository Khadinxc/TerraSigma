resource "azurerm_sentinel_alert_rule_scheduled" "potential_cobaltstrike_service_installations_registry" {
  name                       = "potential_cobaltstrike_service_installations_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential CobaltStrike Service Installations - Registry"
  description                = "Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryValueData contains "ADMIN$" and RegistryValueData contains ".exe") or (RegistryValueData contains "%COMSPEC%" and RegistryValueData contains "start" and RegistryValueData contains "powershell")) and (RegistryKey contains "\\System\\CurrentControlSet\\Services" or (RegistryKey contains "\\System\\ControlSet" and RegistryKey contains "\\Services"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Execution", "PrivilegeEscalation", "LateralMovement"]
  techniques                 = ["T1021", "T1543", "T1569"]
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