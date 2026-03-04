resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_registry_privilege_escalation_via_service_key" {
  name                       = "proc_creation_win_registry_privilege_escalation_via_service_key"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Privilege Escalation via Service Permissions Weakness"
  description                = "Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_registry_privilege_escalation_via_service_key.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_registry_privilege_escalation_via_service_key.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\ImagePath" or ProcessCommandLine contains "\\FailureCommand" or ProcessCommandLine contains "\\ServiceDll") and (ProcessCommandLine contains "ControlSet" and ProcessCommandLine contains "services") and (ProcessIntegrityLevel in~ ("Medium", "S-1-16-8192"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}