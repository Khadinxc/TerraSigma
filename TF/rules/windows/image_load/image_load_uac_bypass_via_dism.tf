resource "azurerm_sentinel_alert_rule_scheduled" "image_load_uac_bypass_via_dism" {
  name                       = "image_load_uac_bypass_via_dism"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass With Fake DLL"
  description                = <<DESC
    Attempts to load dismcore.dll after dropping it

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_uac_bypass_via_dism.yml

    False Positives:
    - Actions of a legitimate telnet client
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\dismcore.dll" and InitiatingProcessFolderPath endswith "\\dism.exe") and (not(FolderPath =~ "C:\\Windows\\System32\\Dism\\dismcore.dll"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548", "T1574"]
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