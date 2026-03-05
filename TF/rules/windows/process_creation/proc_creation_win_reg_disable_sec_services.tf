resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_reg_disable_sec_services" {
  name                       = "proc_creation_win_reg_disable_sec_services"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Security Service Disabled Via Reg.EXE"
  description                = <<DESC
    Detects execution of "reg.exe" to disable security services such as Windows Defender.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_disable_sec_services.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\AppIDSvc" or ProcessCommandLine contains "\\MsMpSvc" or ProcessCommandLine contains "\\NisSrv" or ProcessCommandLine contains "\\SecurityHealthService" or ProcessCommandLine contains "\\Sense" or ProcessCommandLine contains "\\UsoSvc" or ProcessCommandLine contains "\\WdBoot" or ProcessCommandLine contains "\\WdFilter" or ProcessCommandLine contains "\\WdNisDrv" or ProcessCommandLine contains "\\WdNisSvc" or ProcessCommandLine contains "\\WinDefend" or ProcessCommandLine contains "\\wscsvc" or ProcessCommandLine contains "\\wuauserv") and (ProcessCommandLine contains "d 4" and ProcessCommandLine contains "v Start")) and (ProcessCommandLine contains "reg" and ProcessCommandLine contains "add")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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