resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_iexpress_execution" {
  name                       = "proc_creation_win_iexpress_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Self Extracting Package Created Via IExpress.EXE"
  description                = <<DESC
    Detects the "iexpress.exe" utility creating self-extracting packages. Attackers where seen leveraging "iexpress" to compile packages on the fly via ".sed" files. Investigate the command line options provided to "iexpress" and in case of a ".sed" file, check the contents and legitimacy of it.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/process_creation/proc_creation_win_iexpress_execution.yml

    False Positives:
    - Administrators building packages using iexpress.exe
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\makecab.exe" or ProcessVersionInfoOriginalFileName =~ "makecab.exe") and InitiatingProcessFolderPath endswith "\\iexpress.exe") or (ProcessCommandLine contains " /n " and (FolderPath endswith "\\iexpress.exe" or ProcessVersionInfoOriginalFileName =~ "IEXPRESS.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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