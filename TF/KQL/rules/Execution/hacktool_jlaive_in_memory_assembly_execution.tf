resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_jlaive_in_memory_assembly_execution" {
  name                       = "hacktool_jlaive_in_memory_assembly_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Jlaive In-Memory Assembly Execution"
  description                = "Detects the use of Jlaive to execute assemblies in a copied PowerShell"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine endswith ".bat" and InitiatingProcessFolderPath endswith "\\cmd.exe") and (((ProcessCommandLine contains "powershell.exe" and ProcessCommandLine contains ".bat.exe") and FolderPath endswith "\\xcopy.exe") or ((ProcessCommandLine contains "pwsh.exe" and ProcessCommandLine contains ".bat.exe") and FolderPath endswith "\\xcopy.exe") or ((ProcessCommandLine contains "+s" and ProcessCommandLine contains "+h" and ProcessCommandLine contains ".bat.exe") and FolderPath endswith "\\attrib.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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