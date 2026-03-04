resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_apt_apt10_cloud_hopper" {
  name                       = "proc_creation_win_apt_apt10_cloud_hopper"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential APT10 Cloud Hopper Activity"
  description                = "Detects potential process and execution activity related to APT10 Cloud Hopper operation Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2017/TA/APT10/proc_creation_win_apt_apt10_cloud_hopper.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2017/TA/APT10/proc_creation_win_apt_apt10_cloud_hopper.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".vbs /shell " and FolderPath endswith "\\cscript.exe") or (ProcessCommandLine contains "csvde -f C:\\windows\\web\\" and ProcessCommandLine contains ".log")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}