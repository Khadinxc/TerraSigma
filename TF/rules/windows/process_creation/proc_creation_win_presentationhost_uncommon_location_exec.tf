resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_presentationhost_uncommon_location_exec" {
  name                       = "proc_creation_win_presentationhost_uncommon_location_exec"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "XBAP Execution From Uncommon Locations Via PresentationHost.EXE"
  description                = "Detects the execution of \".xbap\" (Browser Applications) files via PresentationHost.EXE from an uncommon location. These files can be abused to run malicious \".xbap\" files any bypass AWL Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_presentationhost_uncommon_location_exec.yml - Legitimate \".xbap\" being executed via \"PresentationHost\" | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_presentationhost_uncommon_location_exec.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".xbap" and (FolderPath endswith "\\presentationhost.exe" or ProcessVersionInfoOriginalFileName =~ "PresentationHost.exe")) and (not((ProcessCommandLine contains " C:\\Windows\\" or ProcessCommandLine contains " C:\\Program Files")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218"]
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