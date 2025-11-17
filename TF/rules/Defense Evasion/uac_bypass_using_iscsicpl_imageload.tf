resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_using_iscsicpl_imageload" {
  name                       = "uac_bypass_using_iscsicpl_imageload"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Using Iscsicpl - ImageLoad"
  description                = "Detects the \"iscsicpl.exe\" UAC bypass technique that leverages a DLL Search Order hijacking technique to load a custom DLL's from temp or a any user controlled location in the users %PATH%"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (InitiatingProcessFolderPath =~ "C:\\Windows\\SysWOW64\\iscsicpl.exe" and FolderPath endswith "\\iscsiexe.dll") and (not((FolderPath contains "C:\\Windows\\" and FolderPath contains "iscsiexe.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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