resource "azurerm_sentinel_alert_rule_scheduled" "windows_recall_feature_enabled_via_reg_exe" {
  name                       = "windows_recall_feature_enabled_via_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Recall Feature Enabled Via Reg.EXE"
  description                = "Detects the enabling of the Windows Recall feature via registry manipulation. Windows Recall can be enabled by deleting the existing \"DisableAIDataAnalysis\" value, or setting it to 0. Adversaries may enable Windows Recall as part of post-exploitation discovery and collection activities. This rule assumes that Recall is already explicitly disabled on the host, and subsequently enabled by the adversary. - Legitimate use/activation of Windows Recall"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe") and (ProcessCommandLine contains "Microsoft\\Windows\\WindowsAI" and ProcessCommandLine contains "DisableAIDataAnalysis") and ((ProcessCommandLine contains "add" or ProcessCommandLine contains "0") or ProcessCommandLine contains "delete")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1113"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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