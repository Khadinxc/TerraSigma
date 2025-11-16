resource "azurerm_sentinel_alert_rule_scheduled" "execution_of_suspicious_file_type_extension" {
  name                       = "execution_of_suspicious_file_type_extension"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Execution of Suspicious File Type Extension"
  description                = "Detects whether the image specified in a process creation event doesn't refer to an \".exe\" (or other known executable extension) file. This can be caused by process ghosting or other unorthodox methods to start a process. This rule might require some initial baselining to align with some third party tooling in the user environment."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (not((FolderPath endswith ".bin" or FolderPath endswith ".cgi" or FolderPath endswith ".com" or FolderPath endswith ".exe" or FolderPath endswith ".scr" or FolderPath endswith ".tmp"))) and (not((FolderPath contains ":\\$Extend\\$Deleted\\" or FolderPath contains ":\\Windows\\System32\\DriverStore\\FileRepository\\" or (FolderPath in~ ("-", "")) or (FolderPath in~ ("System", "Registry", "MemCompression", "vmmem")) or FolderPath contains ":\\Windows\\Installer\\MSI" or (FolderPath contains ":\\Config.Msi\\" and (FolderPath endswith ".rbf" or FolderPath endswith ".rbs")) or isnull(FolderPath) or (InitiatingProcessFolderPath contains ":\\Windows\\Temp\\" or FolderPath contains ":\\Windows\\Temp\\")))) and (not((InitiatingProcessFolderPath contains ":\\ProgramData\\Avira\\" or (FolderPath endswith "com.docker.service" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\services.exe") or FolderPath contains ":\\Program Files\\Mozilla Firefox\\" or FolderPath endswith "\\LZMA_EXE" or (FolderPath endswith ":\\Program Files (x86)\\MyQ\\Server\\pcltool.dll" or FolderPath endswith ":\\Program Files\\MyQ\\Server\\pcltool.dll") or (FolderPath contains "NVIDIA\\NvBackend\\" and FolderPath endswith ".dat") or ((FolderPath contains ":\\Program Files (x86)\\WINPAKPRO\\" or FolderPath contains ":\\Program Files\\WINPAKPRO\\") and FolderPath endswith ".ngn") or (FolderPath contains "\\AppData\\Local\\Packages\\" and FolderPath contains "\\LocalState\\rootfs\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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