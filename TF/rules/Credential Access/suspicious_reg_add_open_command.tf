resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_reg_add_open_command" {
  name                       = "suspicious_reg_add_open_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Reg Add Open Command"
  description                = "Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using DelegateExecute key"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "reg" and ProcessCommandLine contains "add" and ProcessCommandLine contains "hkcu\\software\\classes\\ms-settings\\shell\\open\\command" and ProcessCommandLine contains "/ve " and ProcessCommandLine contains "/d") or (ProcessCommandLine contains "reg" and ProcessCommandLine contains "add" and ProcessCommandLine contains "hkcu\\software\\classes\\ms-settings\\shell\\open\\command" and ProcessCommandLine contains "/v" and ProcessCommandLine contains "DelegateExecute") or (ProcessCommandLine contains "reg" and ProcessCommandLine contains "delete" and ProcessCommandLine contains "hkcu\\software\\classes\\ms-settings")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}