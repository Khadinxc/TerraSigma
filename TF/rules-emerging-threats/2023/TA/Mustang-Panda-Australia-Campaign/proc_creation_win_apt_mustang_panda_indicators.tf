resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_mustang_panda_indicators" {
  name                       = "proc_creation_win_apt_mustang_panda_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential APT Mustang Panda Activity Against Australian Gov"
  description                = <<DESC
    Detects specific command line execution used by Mustang Panda in a targeted attack against the Australian government as reported by Lab52

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/Mustang-Panda-Australia-Campaign/proc_creation_win_apt_mustang_panda_indicators.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "copy SolidPDFCreator.dll" and ProcessCommandLine contains "C:\\Users\\Public\\Libraries\\PhotoTvRHD\\SolidPDFCreator.dll") or (ProcessCommandLine contains "reg " and ProcessCommandLine contains "\\Windows\\CurrentVersion\\Run" and ProcessCommandLine contains "SolidPDF" and ProcessCommandLine contains "C:\\Users\\Public\\Libraries\\PhotoTvRHD\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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