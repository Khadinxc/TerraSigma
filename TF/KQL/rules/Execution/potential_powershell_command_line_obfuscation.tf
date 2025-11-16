resource "azurerm_sentinel_alert_rule_scheduled" "potential_powershell_command_line_obfuscation" {
  name                       = "potential_powershell_command_line_obfuscation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PowerShell Command Line Obfuscation"
  description                = "Detects the PowerShell command lines with special characters - Amazon SSM Document Worker - Windows Defender ATP"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and (ProcessCommandLine matches regex "\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+.*\\+" or ProcessCommandLine matches regex "\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{.*\\{" or ProcessCommandLine matches regex "\\^.*\\^.*\\^.*\\^.*\\^" or ProcessCommandLine matches regex "`.*`.*`.*`.*`")) and (not((InitiatingProcessFolderPath =~ "C:\\Program Files\\Amazon\\SSM\\ssm-document-worker.exe" or (ProcessCommandLine contains "new EventSource(\"Microsoft.Windows.Sense.Client.Management\"" or ProcessCommandLine contains "public static extern bool InstallELAMCertificateInfo(SafeFileHandle handle);"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1027", "T1059"]
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