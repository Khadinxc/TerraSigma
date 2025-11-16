resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_explorer_process_with_whitespace_padding_clickfix_filefix" {
  name                       = "suspicious_explorer_process_with_whitespace_padding_clickfix_filefix"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Explorer Process with Whitespace Padding - ClickFix/FileFix"
  description                = "Detects process creation with suspicious whitespace padding followed by a '#' character, which may indicate ClickFix or FileFix techniques used to conceal malicious commands from visual inspection. ClickFix and FileFix are social engineering attack techniques where adversaries distribute phishing documents or malicious links that deceive users into opening the Windows Run dialog box or File Explorer search bar. The victims are then instructed to paste commands from their clipboard, which contain extensive whitespace padding using various Unicode space characters to push the actual malicious command far to the right, effectively hiding it from immediate view."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "#" and FolderPath endswith "\\explorer.exe") and (ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            " or ProcessCommandLine contains "            ")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1204", "T1027"]
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