resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_crackmapexec_process_patterns" {
  name                       = "hacktool_crackmapexec_process_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - CrackMapExec Process Patterns"
  description                = "Detects suspicious process patterns found in logs when CrackMapExec is used"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "cmd.exe /c " or ProcessCommandLine contains "cmd.exe /r " or ProcessCommandLine contains "cmd.exe /k " or ProcessCommandLine contains "cmd /c " or ProcessCommandLine contains "cmd /r " or ProcessCommandLine contains "cmd /k ") and (ProcessCommandLine contains "tasklist /fi " and ProcessCommandLine contains "Imagename eq lsass.exe") and (AccountName contains "AUTHORI" or AccountName contains "AUTORI")) or (ProcessCommandLine contains "do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump" and ProcessCommandLine contains "\\Windows\\Temp\\" and ProcessCommandLine contains " full" and ProcessCommandLine contains "%%B") or (ProcessCommandLine contains "tasklist /v /fo csv" and ProcessCommandLine contains "findstr /i \"lsass\"")
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