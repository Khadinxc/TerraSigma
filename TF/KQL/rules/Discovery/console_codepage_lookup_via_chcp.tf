resource "azurerm_sentinel_alert_rule_scheduled" "console_codepage_lookup_via_chcp" {
  name                       = "console_codepage_lookup_via_chcp"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Console CodePage Lookup Via CHCP"
  description                = "Detects use of chcp to look up the system locale value as part of host discovery - During Anaconda update the 'conda.exe' process will eventually execution the 'chcp' command. - Discord was seen using chcp to look up code pages"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith "chcp" or ProcessCommandLine endswith "chcp " or ProcessCommandLine endswith "chcp  ") and FolderPath endswith "\\chcp.com" and (InitiatingProcessCommandLine contains " -c " or InitiatingProcessCommandLine contains " /c " or InitiatingProcessCommandLine contains " –c " or InitiatingProcessCommandLine contains " —c " or InitiatingProcessCommandLine contains " ―c " or InitiatingProcessCommandLine contains " -r " or InitiatingProcessCommandLine contains " /r " or InitiatingProcessCommandLine contains " –r " or InitiatingProcessCommandLine contains " —r " or InitiatingProcessCommandLine contains " ―r " or InitiatingProcessCommandLine contains " -k " or InitiatingProcessCommandLine contains " /k " or InitiatingProcessCommandLine contains " –k " or InitiatingProcessCommandLine contains " —k " or InitiatingProcessCommandLine contains " ―k ") and InitiatingProcessFolderPath endswith "\\cmd.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1614"]
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