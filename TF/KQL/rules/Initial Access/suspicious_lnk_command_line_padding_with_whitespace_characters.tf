resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_lnk_command_line_padding_with_whitespace_characters" {
  name                       = "suspicious_lnk_command_line_padding_with_whitespace_characters"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious LNK Command-Line Padding with Whitespace Characters"
  description                = "Detects exploitation of LNK file command-line length discrepancy, where attackers hide malicious commands beyond the 260-character UI limit while the actual command-line argument field supports 4096 characters using whitespace padding (e.g., 0x20, 0x09-0x0D). Adversaries insert non-printable whitespace characters (e.g., Line Feed \\x0A, Carriage Return \\x0D) to pad the visible section of the LNK file, pushing malicious commands past the UI-visible boundary. The hidden payload, executed at runtime but invisible in Windows Explorer properties, enables stealthy execution and evasion—commonly used for social engineering attacks. This rule flags suspicious use of such padding observed in real-world attacks."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "                 " or ProcessCommandLine contains "\\u0009" or ProcessCommandLine contains "\\u000A" or ProcessCommandLine contains "\\u0011" or ProcessCommandLine contains "\\u0012" or ProcessCommandLine contains "\\u0013" or ProcessCommandLine contains "\\u000B" or ProcessCommandLine contains "\\u000C" or ProcessCommandLine contains "\\u000D") or ProcessCommandLine matches regex "\\n\\n\\n\\n\\n\\n") and (InitiatingProcessFolderPath endswith "\\explorer.exe" or InitiatingProcessCommandLine contains ".lnk")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Execution"]
  techniques                 = ["T1204"]
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