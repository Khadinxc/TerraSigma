resource "azurerm_sentinel_alert_rule_scheduled" "image_load_apt_diamond_sleet_side_load" {
  name                       = "image_load_apt_diamond_sleet_side_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Diamond Sleet APT DLL Sideloading Indicators"
  description                = <<DESC
    Detects DLL sideloading activity seen used by Diamond Sleet APT

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/Diamond-Sleet/image_load_apt_diamond_sleet_side_load.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith ":\\ProgramData\\Version.dll" and InitiatingProcessFolderPath endswith ":\\ProgramData\\clip.exe") or (FolderPath endswith ":\\ProgramData\\DSROLE.dll" and InitiatingProcessFolderPath endswith ":\\ProgramData\\wsmprovhost.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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