resource "azurerm_sentinel_alert_rule_scheduled" "python_inline_command_execution" {
  name                       = "python_inline_command_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Python Inline Command Execution"
  description                = "Detects execution of python using the \"-c\" flag. This is could be used as a way to launch a reverse shell or execute live python code. - Python libraries that use a flag starting with \"-c\". Filter according to your environment"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -c" and (ProcessVersionInfoOriginalFileName =~ "python.exe" or (FolderPath endswith "python.exe" or FolderPath endswith "python3.exe" or FolderPath endswith "python2.exe"))) and (not(((InitiatingProcessCommandLine contains "-E -s -m ensurepip -U --default-pip" and InitiatingProcessFolderPath endswith "\\python.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Python" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Python")) or ((ProcessCommandLine contains "-W ignore::DeprecationWarning" and ProcessCommandLine contains "['install', '--no-cache-dir', '--no-index', '--find-links'," and ProcessCommandLine contains "'--upgrade', 'pip'") and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Python" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Python"))))) and (not(((ProcessCommandLine contains "<pip-setuptools-caller>" and ProcessCommandLine contains "exec(compile(") or (InitiatingProcessFolderPath endswith "\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "C:\\Program Files (x86)\\Microsoft VS Code\\Code.exe"))))))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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
  }
}