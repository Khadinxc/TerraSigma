resource "azurerm_sentinel_alert_rule_scheduled" "csc_exe_execution_form_potentially_suspicious_parent" {
  name                       = "csc_exe_execution_form_potentially_suspicious_parent"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Csc.EXE Execution Form Potentially Suspicious Parent"
  description                = "Detects a potentially suspicious parent of \"csc.exe\", which could be a sign of payload delivery."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\csc.exe" or ProcessVersionInfoOriginalFileName =~ "csc.exe") and ((InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\onenote.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe") or ((InitiatingProcessCommandLine contains "-Encoded " or InitiatingProcessCommandLine contains "FromBase64String") and (InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe")) or (InitiatingProcessCommandLine matches regex "([Pp]rogram[Dd]ata|%([Ll]ocal)?[Aa]pp[Dd]ata%|\\\\[Aa]pp[Dd]ata\\\\([Ll]ocal([Ll]ow)?|[Rr]oaming))\\\\[^\\\\]{1,256}$" or (InitiatingProcessCommandLine contains ":\\PerfLogs\\" or InitiatingProcessCommandLine contains ":\\Users\\Public\\" or InitiatingProcessCommandLine contains ":\\Windows\\Temp\\" or InitiatingProcessCommandLine contains "\\Temporary Internet") or (InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\Favorites\\") or (InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\Favourites\\") or (InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\Contacts\\") or (InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\Pictures\\"))) and (not(((InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\") or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\sdiagnhost.exe" or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\inetsrv\\w3wp.exe"))) and (not(((InitiatingProcessCommandLine contains "JwB7ACIAZgBhAGkAbABlAGQAIgA6AHQAcgB1AGUALAAiAG0AcwBnACIAOgAiAEEAbgBzAGkAYgBsAGUAIAByAGUAcQB1AGkAcgBlAHMAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAdgAzAC4AMAAgAG8AcgAgAG4AZQB3AGUAcgAiAH0AJw" or InitiatingProcessCommandLine contains "cAewAiAGYAYQBpAGwAZQBkACIAOgB0AHIAdQBlACwAIgBtAHMAZwAiADoAIgBBAG4AcwBpAGIAbABlACAAcgBlAHEAdQBpAHIAZQBzACAAUABvAHcAZQByAFMAaABlAGwAbAAgAHYAMwAuADAAIABvAHIAIABuAGUAdwBlAHIAIgB9ACcA" or InitiatingProcessCommandLine contains "nAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnA") or InitiatingProcessFolderPath =~ "C:\\ProgramData\\chocolatey\\choco.exe" or InitiatingProcessCommandLine contains "\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1218", "T1027"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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