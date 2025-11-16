resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_soaphound_execution" {
  name                       = "hacktool_soaphound_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - SOAPHound Execution"
  description                = "Detects the execution of SOAPHound, a .NET tool for collecting Active Directory data, using specific command-line arguments that may indicate an attempt to extract sensitive AD information."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " --buildcache " or ProcessCommandLine contains " --bhdump " or ProcessCommandLine contains " --certdump " or ProcessCommandLine contains " --dnsdump ") and (ProcessCommandLine contains " -c " or ProcessCommandLine contains " --cachefilename " or ProcessCommandLine contains " -o " or ProcessCommandLine contains " --outputdirectory")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1087"]
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
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
  }
}