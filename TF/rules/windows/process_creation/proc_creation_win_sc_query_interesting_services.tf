resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_sc_query_interesting_services" {
  name                       = "proc_creation_win_sc_query_interesting_services"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Interesting Service Enumeration Via Sc.EXE"
  description                = <<DESC
    Detects the enumeration and query of interesting and in some cases sensitive services on the system via "sc.exe". Attackers often try to enumerate the services currently running on a system in order to find different attack vectors.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sc_query_interesting_services.yml
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "query" and ProcessCommandLine contains "termservice" and (FolderPath endswith "\\sc.exe" or ProcessVersionInfoOriginalFileName =~ "sc.exe")
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}