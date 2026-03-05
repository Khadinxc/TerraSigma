resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_renamed_sysinternals_procdump" {
  name                       = "proc_creation_win_renamed_sysinternals_procdump"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed ProcDump Execution"
  description                = <<DESC
    Detects the execution of a renamed ProcDump executable. This often done by attackers or malware in order to evade defensive mechanisms.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml

    False Positives:
    - Procdump illegally bundled with legitimate software.
    - Administrators who rename binaries (should be investigated).
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoOriginalFileName =~ "procdump" or ((ProcessCommandLine contains " -ma " or ProcessCommandLine contains " /ma " or ProcessCommandLine contains " –ma " or ProcessCommandLine contains " —ma " or ProcessCommandLine contains " ―ma " or ProcessCommandLine contains " -mp " or ProcessCommandLine contains " /mp " or ProcessCommandLine contains " –mp " or ProcessCommandLine contains " —mp " or ProcessCommandLine contains " ―mp ") and (ProcessCommandLine contains " -accepteula" or ProcessCommandLine contains " /accepteula" or ProcessCommandLine contains " –accepteula" or ProcessCommandLine contains " —accepteula" or ProcessCommandLine contains " ―accepteula"))) and (not((FolderPath endswith "\\procdump.exe" or FolderPath endswith "\\procdump64.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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