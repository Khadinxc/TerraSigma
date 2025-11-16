resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_empire_powershell_launch_parameters" {
  name                       = "hacktool_empire_powershell_launch_parameters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Empire PowerShell Launch Parameters"
  description                = "Detects suspicious powershell command line parameters used in Empire - Other tools that incidentally use the same command line parameters"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " -NoP -sta -NonI -W Hidden -Enc " or ProcessCommandLine contains " -noP -sta -w 1 -enc " or ProcessCommandLine contains " -NoP -NonI -W Hidden -enc " or ProcessCommandLine contains " -noP -sta -w 1 -enc" or ProcessCommandLine contains " -enc  SQB" or ProcessCommandLine contains " -nop -exec bypass -EncodedCommand "
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
  }
}