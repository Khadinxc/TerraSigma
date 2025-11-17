resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_crackmapexec_execution_patterns" {
  name                       = "hacktool_crackmapexec_execution_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - CrackMapExec Execution Patterns"
  description                = "Detects various execution patterns of the CrackMapExec pentesting framework"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "cmd.exe /Q /c " and ProcessCommandLine contains " 1> \\" and ProcessCommandLine contains "\\" and ProcessCommandLine contains "\\" and ProcessCommandLine contains " 2>&1") or (ProcessCommandLine contains "cmd.exe /C " and ProcessCommandLine contains " > \\" and ProcessCommandLine contains "\\" and ProcessCommandLine contains "\\" and ProcessCommandLine contains " 2>&1") or (ProcessCommandLine contains "cmd.exe /C " and ProcessCommandLine contains " > " and ProcessCommandLine contains "\\Temp\\" and ProcessCommandLine contains " 2>&1") or ProcessCommandLine contains "powershell.exe -exec bypass -noni -nop -w 1 -C \"" or ProcessCommandLine contains "powershell.exe -noni -nop -w 1 -enc "
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "Execution"]
  techniques                 = ["T1047", "T1053", "T1059"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}