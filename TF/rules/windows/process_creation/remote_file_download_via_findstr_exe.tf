resource "azurerm_sentinel_alert_rule_scheduled" "remote_file_download_via_findstr_exe" {
  name                       = "remote_file_download_via_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote File Download Via Findstr.EXE"
  description                = "Detects execution of \"findstr\" with specific flags and a remote share path. This specific set of CLI flags would allow \"findstr\" to download the content of the file located on the remote share as described in the LOLBAS entry."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "findstr" or FolderPath endswith "findstr.exe" or ProcessVersionInfoOriginalFileName =~ "FINDSTR.EXE") and ((ProcessCommandLine contains " -v " or ProcessCommandLine contains " /v " or ProcessCommandLine contains " –v " or ProcessCommandLine contains " —v " or ProcessCommandLine contains " ―v ") and (ProcessCommandLine contains " -l " or ProcessCommandLine contains " /l " or ProcessCommandLine contains " –l " or ProcessCommandLine contains " —l " or ProcessCommandLine contains " ―l ") and ProcessCommandLine contains "\\\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess", "CommandAndControl"]
  techniques                 = ["T1218", "T1564", "T1552", "T1105"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}