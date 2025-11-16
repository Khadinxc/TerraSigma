resource "azurerm_sentinel_alert_rule_scheduled" "python_image_load_by_non_python_process" {
  name                       = "python_image_load_by_non_python_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Image Load By Non-Python Process"
  description                = "Detects the image load of \"Python Core\" by a non-Python process. This might be indicative of a execution of executable that has been bundled from Python code. Various tools like Py2Exe, PyInstaller, and cx_Freeze are used to bundle Python code into standalone executables. Threat actors often use these tools to bundle malicious Python scripts into executables, sometimes to obfuscate the code or to bypass security measures. - Legitimate Py2Exe Binaries - Known false positive caused with Python Anaconda - Various legitimate software is bundled from Python code into executables"
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where InitiatingProcessVersionInfoFileDescription =~ "Python Core" and (not((InitiatingProcessFolderPath contains "Python" or (InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\ProgramData\\Anaconda3\\")))) and (not(isnull(InitiatingProcessFolderPath)))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1027"]
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