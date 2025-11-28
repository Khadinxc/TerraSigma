resource "azurerm_sentinel_alert_rule_scheduled" "hermetic_wiper_tg_process_patterns" {
  name                       = "hermetic_wiper_tg_process_patterns"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Hermetic Wiper TG Process Patterns"
  description                = "Detects process execution patterns found in intrusions related to the Hermetic Wiper malware attacks against Ukraine in February 2022"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\policydefinitions\\postgresql.exe" or ((ProcessCommandLine contains "CSIDL_SYSTEM_DRIVE\\temp\\sys.tmp" or ProcessCommandLine contains " 1> \\\\127.0.0.1\\ADMIN$\\__16") or (ProcessCommandLine contains "powershell -c " and ProcessCommandLine contains "\\comsvcs.dll MiniDump " and ProcessCommandLine contains "\\winupd.log full"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement"]
  techniques                 = ["T1021"]
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

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}