resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_parent_double_extension_file_execution" {
  name                       = "suspicious_parent_double_extension_file_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Parent Double Extension File Execution"
  description                = "Detect execution of suspicious double extension files in ParentCommandLine"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith ".doc.lnk" or InitiatingProcessFolderPath endswith ".docx.lnk" or InitiatingProcessFolderPath endswith ".xls.lnk" or InitiatingProcessFolderPath endswith ".xlsx.lnk" or InitiatingProcessFolderPath endswith ".ppt.lnk" or InitiatingProcessFolderPath endswith ".pptx.lnk" or InitiatingProcessFolderPath endswith ".rtf.lnk" or InitiatingProcessFolderPath endswith ".pdf.lnk" or InitiatingProcessFolderPath endswith ".txt.lnk" or InitiatingProcessFolderPath endswith ".doc.js" or InitiatingProcessFolderPath endswith ".docx.js" or InitiatingProcessFolderPath endswith ".xls.js" or InitiatingProcessFolderPath endswith ".xlsx.js" or InitiatingProcessFolderPath endswith ".ppt.js" or InitiatingProcessFolderPath endswith ".pptx.js" or InitiatingProcessFolderPath endswith ".rtf.js" or InitiatingProcessFolderPath endswith ".pdf.js" or InitiatingProcessFolderPath endswith ".txt.js") or (InitiatingProcessCommandLine contains ".doc.lnk" or InitiatingProcessCommandLine contains ".docx.lnk" or InitiatingProcessCommandLine contains ".xls.lnk" or InitiatingProcessCommandLine contains ".xlsx.lnk" or InitiatingProcessCommandLine contains ".ppt.lnk" or InitiatingProcessCommandLine contains ".pptx.lnk" or InitiatingProcessCommandLine contains ".rtf.lnk" or InitiatingProcessCommandLine contains ".pdf.lnk" or InitiatingProcessCommandLine contains ".txt.lnk" or InitiatingProcessCommandLine contains ".doc.js" or InitiatingProcessCommandLine contains ".docx.js" or InitiatingProcessCommandLine contains ".xls.js" or InitiatingProcessCommandLine contains ".xlsx.js" or InitiatingProcessCommandLine contains ".ppt.js" or InitiatingProcessCommandLine contains ".pptx.js" or InitiatingProcessCommandLine contains ".rtf.js" or InitiatingProcessCommandLine contains ".pdf.js" or InitiatingProcessCommandLine contains ".txt.js")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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