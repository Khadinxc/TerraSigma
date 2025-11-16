resource "azurerm_sentinel_alert_rule_scheduled" "awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl_file" {
  name                       = "awl_bypass_with_winrm_vbs_and_malicious_wsmpty_xsl_wsmtxt_xsl_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl - File"
  description                = "Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed) - Unlikely"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "WsmPty.xsl" or FolderPath endswith "WsmTxt.xsl") and (not((FolderPath startswith "C:\\Windows\\System32\\" or FolderPath startswith "C:\\Windows\\SysWOW64\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1216"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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