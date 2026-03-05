resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_shadowcopy_deletion" {
  name                       = "proc_creation_win_powershell_shadowcopy_deletion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Deletion of Volume Shadow Copies via WMI with PowerShell"
  description                = <<DESC
    Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_shadowcopy_deletion.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".Delete()" or ProcessCommandLine contains "Remove-WmiObject" or ProcessCommandLine contains "rwmi" or ProcessCommandLine contains "Remove-CimInstance" or ProcessCommandLine contains "rcim") and (ProcessCommandLine contains "Get-WmiObject" or ProcessCommandLine contains "gwmi" or ProcessCommandLine contains "Get-CimInstance" or ProcessCommandLine contains "gcim") and ProcessCommandLine contains "Win32_ShadowCopy"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1490"]
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