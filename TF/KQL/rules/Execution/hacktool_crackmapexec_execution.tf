resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_crackmapexec_execution" {
  name                       = "hacktool_crackmapexec_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - CrackMapExec Execution"
  description                = "This rule detect common flag combinations used by CrackMapExec in order to detect its use even if the binary has been replaced."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\crackmapexec.exe" or (ProcessCommandLine contains " --local-auth" and ProcessCommandLine contains " -u " and ProcessCommandLine contains " -x ") or (ProcessCommandLine contains " --local-auth" and ProcessCommandLine contains " -u " and ProcessCommandLine contains " -p " and ProcessCommandLine contains " -H 'NTHASH'") or (ProcessCommandLine contains " mssql " and ProcessCommandLine contains " -u " and ProcessCommandLine contains " -p " and ProcessCommandLine contains " -M " and ProcessCommandLine contains " -d ") or (ProcessCommandLine contains " smb " and ProcessCommandLine contains " -u " and ProcessCommandLine contains " -H " and ProcessCommandLine contains " -M " and ProcessCommandLine contains " -o ") or (ProcessCommandLine contains " smb " and ProcessCommandLine contains " -u " and ProcessCommandLine contains " -p " and ProcessCommandLine contains " --local-auth") or ProcessCommandLine contains " -M pe_inject ") or ((ProcessCommandLine contains " --local-auth" and ProcessCommandLine contains " -u " and ProcessCommandLine contains " -p ") and (ProcessCommandLine contains " 10." and ProcessCommandLine contains " 192.168." and ProcessCommandLine contains "/24 "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence", "PrivilegeEscalation", "CredentialAccess", "Discovery"]
  techniques                 = ["T1047", "T1053", "T1059", "T1110", "T1201"]
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