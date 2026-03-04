resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_use_of_vsjitdebugger_bin" {
  name                       = "proc_creation_win_susp_use_of_vsjitdebugger_bin"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Malicious PE Execution by Microsoft Visual Studio Debugger"
  description                = "There is an option for a MS VS Just-In-Time Debugger \"vsjitdebugger.exe\" to launch specified executable and attach a debugger. This option may be used adversaries to execute malicious code by signed verified binary. The debugger is installed alongside with Microsoft Visual Studio package. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_use_of_vsjitdebugger_bin.yml - The process spawned by vsjitdebugger.exe is uncommon. | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_use_of_vsjitdebugger_bin.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\vsjitdebugger.exe" and (not(((FolderPath contains "\\vsimmersiveactivatehelper" and FolderPath contains ".exe") or FolderPath endswith "\\devenv.exe")))
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}