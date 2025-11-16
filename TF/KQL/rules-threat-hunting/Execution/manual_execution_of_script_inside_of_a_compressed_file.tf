resource "azurerm_sentinel_alert_rule_scheduled" "manual_execution_of_script_inside_of_a_compressed_file" {
  name                       = "manual_execution_of_script_inside_of_a_compressed_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Manual Execution of Script Inside of a Compressed File"
  description                = "This is a threat-hunting query to collect information related to the interactive execution of a script from inside a compressed file (zip/rar). Windows will automatically run the script using scripting interpreters such as wscript and cscript binaries. From the query below, the child process is the script interpreter that will execute the script. The script extension is also a set of standard extensions that Windows OS recognizes. Selections 1-3 contain three different execution scenarios. 1. Compressed file opened using 7zip. 2. Compressed file opened using WinRar. 3. Compressed file opened using native windows File Explorer capabilities. When the malicious script is double-clicked, it will be extracted to the respected directories as signified by the CommandLine on each of the three Selections. It will then be executed using the relevant script interpreter.\" - Batch files may produce a lot of noise, as many applications appear to bundle them as part of their installation process. You should baseline your environment and generate a new query excluding the noisy and expected activity. Some false positives may come up depending on your environment. All results should be investigated thoroughly before filtering out results."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine =~ "*\\AppData\\local\\temp\\7z*\*" and InitiatingProcessFolderPath =~ "*\\7z*.exe") or ((ProcessCommandLine contains "\\AppData\\local\\temp*.rar\\" or ProcessCommandLine contains "\\AppData\\local\\temp*.zip\\") and InitiatingProcessFolderPath endswith "\\explorer.exe") or (ProcessCommandLine =~ "*\\AppData\\local\\temp\\rar*\*" and InitiatingProcessFolderPath endswith "\\winrar.exe")) and ((ProcessCommandLine endswith ".hta" or ProcessCommandLine endswith ".js" or ProcessCommandLine endswith ".jse" or ProcessCommandLine endswith ".ps1" or ProcessCommandLine endswith ".vbe" or ProcessCommandLine endswith ".vbs" or ProcessCommandLine endswith ".wsf" or ProcessCommandLine endswith ".wsh") and (FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe"))
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