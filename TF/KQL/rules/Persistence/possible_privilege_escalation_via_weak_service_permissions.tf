resource "azurerm_sentinel_alert_rule_scheduled" "possible_privilege_escalation_via_weak_service_permissions" {
  name                       = "possible_privilege_escalation_via_weak_service_permissions"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Possible Privilege Escalation via Weak Service Permissions"
  description                = "Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\sc.exe" and (ProcessIntegrityLevel in~ ("Medium", "S-1-16-8192"))) and ((ProcessCommandLine contains "config" and ProcessCommandLine contains "binPath") or (ProcessCommandLine contains "failure" and ProcessCommandLine contains "command"))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}