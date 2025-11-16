resource "azurerm_sentinel_alert_rule_scheduled" "potential_product_class_reconnaissance_via_wmic_exe" {
  name                       = "potential_product_class_reconnaissance_via_wmic_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Product Class Reconnaissance Via Wmic.EXE"
  description                = "Detects the execution of WMIC in order to get a list of firewall, antivirus and antispywware products. Adversaries often enumerate security products installed on a system to identify security controls and potential ways to evade detection or disable protection mechanisms. This information helps them plan their next attack steps and choose appropriate techniques to bypass security measures. - Legitimate use of wmic.exe for reconnaissance of firewall, antivirus and antispywware products."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "AntiVirusProduct" or ProcessCommandLine contains "AntiSpywareProduct" or ProcessCommandLine contains "FirewallProduct") and (FolderPath endswith "\\wmic.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Discovery"]
  techniques                 = ["T1047", "T1082"]
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