resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_csi_execution" {
  name                       = "proc_creation_win_csi_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Csi.exe Usage"
  description                = <<DESC
    Csi.exe is a signed binary from Microsoft that comes with Visual Studio and provides C# interactive capabilities. It can be used to run C# code from a file passed as a parameter in command line. Early version of this utility provided with Microsoft “Roslyn” Community Technology Preview was named 'rcsi.exe'

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_csi_execution.yml

    False Positives:
    - Legitimate usage by software developers
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoCompanyName =~ "Microsoft Corporation" and ((FolderPath endswith "\\csi.exe" or FolderPath endswith "\\rcsi.exe") or (ProcessVersionInfoOriginalFileName in~ ("csi.exe", "rcsi.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "Execution", "DefenseEvasion"]
  techniques                 = ["T1072", "T1218"]
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