resource "azurerm_sentinel_alert_rule_scheduled" "potential_process_injection_via_msra_exe" {
  name                       = "potential_process_injection_via_msra_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Process Injection Via Msra.EXE"
  description                = "Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics - Legitimate use of Msra.exe"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\arp.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\netstat.exe" or FolderPath endswith "\\nslookup.exe" or FolderPath endswith "\\route.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\whoami.exe") and InitiatingProcessCommandLine endswith "msra.exe" and InitiatingProcessFolderPath endswith "\\msra.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1055"]
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