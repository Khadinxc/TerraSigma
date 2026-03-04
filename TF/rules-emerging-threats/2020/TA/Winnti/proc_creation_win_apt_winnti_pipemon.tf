resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_winnti_pipemon" {
  name                       = "proc_creation_win_apt_winnti_pipemon"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Winnti Pipemon Characteristics"
  description                = "Detects specific process characteristics of Winnti Pipemon malware reported by ESET Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2020/TA/Winnti/proc_creation_win_apt_winnti_pipemon.yml - Legitimate setups that use similar flags | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2020/TA/Winnti/proc_creation_win_apt_winnti_pipemon.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "setup0.exe -p" or (ProcessCommandLine contains "setup.exe" and (ProcessCommandLine endswith "-x:0" or ProcessCommandLine endswith "-x:1" or ProcessCommandLine endswith "-x:2"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1574"]
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