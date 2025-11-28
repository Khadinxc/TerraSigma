resource "azurerm_sentinel_alert_rule_scheduled" "python_path_configuration_file_creation_macos" {
  name                       = "python_path_configuration_file_creation_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Path Configuration File Creation - MacOS"
  description                = "Detects creation of a Python path configuration file (.pth) in Python library folders, which can be maliciously abused for code execution and persistence. Modules referenced by these files are run at every Python startup (v3.5+), regardless of whether the module is imported by the calling script. Default paths are '\\lib\\site-packages\\*.pth' (Windows) and '/lib/pythonX.Y/site-packages/*.pth' (Unix and macOS). - Although .pth files are discouraged due to potential security implications, these are legitimate files by specification."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".pth" and FolderPath matches regex "(?i)/lib/python3\\.([5-9]|[0-9]{2})/site-packages/"
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