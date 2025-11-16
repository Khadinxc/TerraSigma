resource "azurerm_sentinel_alert_rule_scheduled" "explorer_nouaccheck_flag" {
  name                       = "explorer_nouaccheck_flag"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Explorer NOUACCHECK Flag"
  description                = "Detects suspicious starts of explorer.exe that use the /NOUACCHECK flag that allows to run all sub processes of that newly started explorer.exe without any UAC checks - Domain Controller User Logon - Unknown how many legitimate software products use that method"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/NOUACCHECK" and FolderPath endswith "\\explorer.exe") and (not((InitiatingProcessCommandLine =~ "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule" or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\svchost.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1548"]
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