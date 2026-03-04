resource "azurerm_sentinel_alert_rule_scheduled" "image_load_scrcons_wmi_scripteventconsumer" {
  name                       = "image_load_scrcons_wmi_scripteventconsumer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load"
  description                = "Detects signs of the WMI script host process \"scrcons.exe\" loading scripting DLLs which could indicates WMI ActiveScriptEventConsumers EventConsumers activity. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_scrcons_wmi_scripteventconsumer.yml - Legitimate event consumers - Dell computers on some versions register an event consumer that is known to cause false positives when brightness is changed by the corresponding keyboard button | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_scrcons_wmi_scripteventconsumer.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\vbscript.dll" or FolderPath endswith "\\wbemdisp.dll" or FolderPath endswith "\\wshom.ocx" or FolderPath endswith "\\scrrun.dll") and InitiatingProcessFolderPath endswith "\\scrcons.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1546"]
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