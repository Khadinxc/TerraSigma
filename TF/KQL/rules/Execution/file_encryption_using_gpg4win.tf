resource "azurerm_sentinel_alert_rule_scheduled" "file_encryption_using_gpg4win" {
  name                       = "file_encryption_using_gpg4win"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Encryption Using Gpg4win"
  description                = "Detects usage of Gpg4win to encrypt files"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -c " and ProcessCommandLine contains "passphrase") and ((FolderPath endswith "\\gpg.exe" or FolderPath endswith "\\gpg2.exe") or ProcessVersionInfoFileDescription =~ "GnuPG’s OpenPGP tool")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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