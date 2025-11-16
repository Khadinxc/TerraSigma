resource "azurerm_sentinel_alert_rule_scheduled" "unusual_parent_process_for_cmd_exe" {
  name                       = "unusual_parent_process_for_cmd_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Unusual Parent Process For Cmd.EXE"
  description                = "Detects suspicious parent process for cmd.exe"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\cmd.exe" and (InitiatingProcessFolderPath endswith "\\csrss.exe" or InitiatingProcessFolderPath endswith "\\ctfmon.exe" or InitiatingProcessFolderPath endswith "\\dllhost.exe" or InitiatingProcessFolderPath endswith "\\epad.exe" or InitiatingProcessFolderPath endswith "\\FlashPlayerUpdateService.exe" or InitiatingProcessFolderPath endswith "\\GoogleUpdate.exe" or InitiatingProcessFolderPath endswith "\\jucheck.exe" or InitiatingProcessFolderPath endswith "\\jusched.exe" or InitiatingProcessFolderPath endswith "\\LogonUI.exe" or InitiatingProcessFolderPath endswith "\\lsass.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\SearchIndexer.exe" or InitiatingProcessFolderPath endswith "\\SearchProtocolHost.exe" or InitiatingProcessFolderPath endswith "\\SIHClient.exe" or InitiatingProcessFolderPath endswith "\\sihost.exe" or InitiatingProcessFolderPath endswith "\\slui.exe" or InitiatingProcessFolderPath endswith "\\spoolsv.exe" or InitiatingProcessFolderPath endswith "\\sppsvc.exe" or InitiatingProcessFolderPath endswith "\\taskhostw.exe" or InitiatingProcessFolderPath endswith "\\unsecapp.exe" or InitiatingProcessFolderPath endswith "\\WerFault.exe" or InitiatingProcessFolderPath endswith "\\wermgr.exe" or InitiatingProcessFolderPath endswith "\\wlanext.exe" or InitiatingProcessFolderPath endswith "\\WUDFHost.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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