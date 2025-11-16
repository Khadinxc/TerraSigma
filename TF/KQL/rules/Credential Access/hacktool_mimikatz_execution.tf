resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_mimikatz_execution" {
  name                       = "hacktool_mimikatz_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Mimikatz Execution"
  description                = "Detection well-known mimikatz command line arguments - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "::aadcookie" or ProcessCommandLine contains "::detours" or ProcessCommandLine contains "::memssp" or ProcessCommandLine contains "::mflt" or ProcessCommandLine contains "::ncroutemon" or ProcessCommandLine contains "::ngcsign" or ProcessCommandLine contains "::printnightmare" or ProcessCommandLine contains "::skeleton" or ProcessCommandLine contains "::preshutdown" or ProcessCommandLine contains "::mstsc" or ProcessCommandLine contains "::multirdp") or (ProcessCommandLine contains "rpc::" or ProcessCommandLine contains "token::" or ProcessCommandLine contains "crypto::" or ProcessCommandLine contains "dpapi::" or ProcessCommandLine contains "sekurlsa::" or ProcessCommandLine contains "kerberos::" or ProcessCommandLine contains "lsadump::" or ProcessCommandLine contains "privilege::" or ProcessCommandLine contains "process::" or ProcessCommandLine contains "vault::") or (ProcessCommandLine contains "DumpCreds" or ProcessCommandLine contains "mimikatz")
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