resource "azurerm_sentinel_alert_rule_scheduled" "werfaultsecure_loading_dbgcore_or_dbghelp_edr_freeze" {
  name                       = "werfaultsecure_loading_dbgcore_or_dbghelp_edr_freeze"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WerFaultSecure Loading DbgCore or DbgHelp - EDR-Freeze"
  description                = "Detects WerFaultSecure.exe loading dbgcore.dll or dbghelp.dll which contains the MiniDumpWriteDump function. The MiniDumpWriteDump function creates a minidump of a process by suspending all threads in the target process to ensure a consistent memory snapshot. The EDR-Freeze technique abuses WerFaultSecure.exe running as a Protected Process Light (PPL) with WinTCB protection level to suspend EDR/AV processes. By leveraging MiniDumpWriteDump's thread suspension behavior, edr-freeze allows malicious activity to execute undetected during the suspension period."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\dbgcore.dll" or FolderPath endswith "\\dbghelp.dll") and InitiatingProcessFolderPath endswith "\\WerFaultSecure.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}