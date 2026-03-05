resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_use_of_te_bin" {
  name                       = "proc_creation_win_susp_use_of_te_bin"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Malicious Windows Script Components File Execution by TAEF Detection"
  description                = <<DESC
    Windows Test Authoring and Execution Framework (TAEF) framework allows you to run automation by executing tests files written on different languages (C, C#, Microsoft COM Scripting interfaces Adversaries may execute malicious code (such as WSC file with VBScript, dll and so on) directly by running te.exe

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_use_of_te_bin.yml

    False Positives:
    - It's not an uncommon to use te.exe directly to execute legal TAEF tests
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\te.exe" or InitiatingProcessFolderPath endswith "\\te.exe" or ProcessVersionInfoOriginalFileName =~ "\\te.exe"
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}