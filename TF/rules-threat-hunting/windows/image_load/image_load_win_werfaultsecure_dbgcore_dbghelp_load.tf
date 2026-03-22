resource "azurerm_sentinel_alert_rule_scheduled" "image_load_win_werfaultsecure_dbgcore_dbghelp_load" {
  name                       = "image_load_win_werfaultsecure_dbgcore_dbghelp_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WerFaultSecure Loading DbgCore or DbgHelp - EDR-Freeze"
  description                = <<DESC
    Detects the loading of dbgcore.dll or dbghelp.dll by WerFaultSecure.exe, which has been observed in EDR-Freeze attacks to suspend processes and evade detection. However, this behavior has also been observed during normal software installations, so further investigation is required to confirm malicious activity. When threat hunting, look for this activity in conjunction with other suspicious processes starting, network connections, or file modifications that occur shortly after the DLL load. Pay special attention to timing - if other malicious activities occur during or immediately after this library loading, it may indicate EDR evasion attempts. Also correlate with any EDR/AV process suspension events or gaps in security monitoring during the timeframe.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-threat-hunting/windows/image_load/image_load_win_werfaultsecure_dbgcore_dbghelp_load.yml
  DESC
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