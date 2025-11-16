resource "azurerm_sentinel_alert_rule_scheduled" "potential_suspicious_activity_using_secedit" {
  name                       = "potential_suspicious_activity_using_secedit"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Activity Using SeCEdit"
  description                = "Detects potential suspicious behaviour using secedit.exe. Such as exporting or modifying the security policy - Legitimate administrative use"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\secedit.exe" or ProcessVersionInfoOriginalFileName =~ "SeCEdit") and ((ProcessCommandLine contains "/configure" and ProcessCommandLine contains "/db") or (ProcessCommandLine contains "/export" and ProcessCommandLine contains "/cfg"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "Discovery", "Persistence", "DefenseEvasion", "CredentialAccess", "PrivilegeEscalation"]
  techniques                 = ["T1562", "T1547", "T1505", "T1556", "T1574", "T1564", "T1546", "T1557", "T1082"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}