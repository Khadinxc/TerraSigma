resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_impersonate_execution" {
  name                       = "hacktool_impersonate_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Impersonate Execution"
  description                = "Detects execution of the Impersonate tool. Which can be used to manipulate tokens on a Windows computers remotely (PsExec/WmiExec) or interactively"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "impersonate.exe" and (ProcessCommandLine contains " list " or ProcessCommandLine contains " exec " or ProcessCommandLine contains " adduser ")) or (MD5 startswith "9520714AB576B0ED01D1513691377D01" or SHA256 startswith "E81CC96E2118DC4FBFE5BAD1604E0AC7681960143E2101E1A024D52264BB0A8A")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1134"]
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