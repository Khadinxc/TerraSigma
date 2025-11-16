resource "azurerm_sentinel_alert_rule_scheduled" "pua_process_hacker_execution" {
  name                       = "pua_process_hacker_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Process Hacker Execution"
  description                = "Detects the execution of Process Hacker based on binary metadata information (Image, Hash, Imphash, etc). Process Hacker is a tool to view and manipulate processes, kernel options and other low level options. Threat actors abused older vulnerable versions to manipulate system processes. - While sometimes 'Process Hacker is used by legitimate administrators, the execution of Process Hacker must be investigated and allowed on a case by case basis"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath contains "\\ProcessHacker_" or FolderPath endswith "\\ProcessHacker.exe" or (ProcessVersionInfoOriginalFileName in~ ("ProcessHacker.exe", "Process Hacker")) or ProcessVersionInfoFileDescription =~ "Process Hacker" or ProcessVersionInfoProductName =~ "Process Hacker" or ((MD5 startswith "68F9B52895F4D34E74112F3129B3B00D" or MD5 startswith "B365AF317AE730A67C936F21432B9C71") or (SHA1 startswith "A0BDFAC3CE1880B32FF9B696458327CE352E3B1D" or SHA1 startswith "C5E2018BF7C0F314FED4FD7FE7E69FA2E648359E") or (SHA256 startswith "D4A0FE56316A2C45B9BA9AC1005363309A3EDC7ACF9E4DF64D326A0FF273E80F" or SHA256 startswith "BD2C2CF0631D881ED382817AFCCE2B093F4E412FFB170A719E2762F250ABFEA4"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Discovery", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1622", "T1564", "T1543"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
    field_mapping {
      identifier  = "SHA1"
      column_name = "SHA1"
    }
    field_mapping {
      identifier  = "SHA256"
      column_name = "SHA256"
    }
    field_mapping {
      identifier  = "MD5"
      column_name = "MD5"
    }
  }
}