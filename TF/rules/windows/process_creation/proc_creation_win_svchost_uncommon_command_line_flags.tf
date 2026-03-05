resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_svchost_uncommon_command_line_flags" {
  name                       = "proc_creation_win_svchost_uncommon_command_line_flags"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Svchost Command Line Parameter"
  description                = <<DESC
    Detects instances of svchost.exe running with an unusual or uncommon command line parameter by excluding known legitimate or common patterns. This could point at a file masquerading as svchost, a process injection, or hollowing of a legitimate svchost instance.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_svchost_uncommon_command_line_flags.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\svchost.exe" and (not((ProcessCommandLine =~ "" or ProcessCommandLine matches regex "-k\\s\\w{1,64}(\\s?(-p|-s))?" or isnull(ProcessCommandLine)))) and (not(((ProcessCommandLine contains "svchost.exe" and InitiatingProcessFolderPath endswith "\\MsMpEng.exe") or (ProcessCommandLine =~ "svchost.exe" and InitiatingProcessFolderPath endswith "\\MRT.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1036", "T1055"]
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