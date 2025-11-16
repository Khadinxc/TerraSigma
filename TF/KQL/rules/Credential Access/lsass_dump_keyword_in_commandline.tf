resource "azurerm_sentinel_alert_rule_scheduled" "lsass_dump_keyword_in_commandline" {
  name                       = "lsass_dump_keyword_in_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LSASS Dump Keyword In CommandLine"
  description                = "Detects the presence of the keywords \"lsass\" and \".dmp\" in the commandline, which could indicate a potential attempt to dump or create a dump of the lsass process. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "lsass.dmp" or ProcessCommandLine contains "lsass.zip" or ProcessCommandLine contains "lsass.rar" or ProcessCommandLine contains "Andrew.dmp" or ProcessCommandLine contains "Coredump.dmp" or ProcessCommandLine contains "NotLSASS.zip" or ProcessCommandLine contains "lsass_2" or ProcessCommandLine contains "lsassdump" or ProcessCommandLine contains "lsassdmp") or (ProcessCommandLine contains "lsass" and ProcessCommandLine contains ".dmp") or (ProcessCommandLine contains "SQLDmpr" and ProcessCommandLine contains ".mdmp") or (ProcessCommandLine contains "nanodump" and ProcessCommandLine contains ".dmp")
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}