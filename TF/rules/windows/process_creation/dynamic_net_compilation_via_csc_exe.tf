resource "azurerm_sentinel_alert_rule_scheduled" "dynamic_net_compilation_via_csc_exe" {
  name                       = "dynamic_net_compilation_via_csc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Dynamic .NET Compilation Via Csc.EXE"
  description                = "Detects execution of \"csc.exe\" to compile .NET code. Attackers often leverage this to compile code on the fly and use it in other stages. - Legitimate software from program files - https://twitter.com/gN3mes1s/status/1206874118282448897 - Legitimate Microsoft software - https://twitter.com/gabriele_pippi/status/1206907900268072962 - Ansible"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\csc.exe" and ((ProcessCommandLine contains ":\\Perflogs\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\Temporary Internet" or ProcessCommandLine contains "\\Windows\\Temp\\") or ((ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Favorites\\") or (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Favourites\\") or (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Contacts\\") or (ProcessCommandLine contains ":\\Users\\" and ProcessCommandLine contains "\\Pictures\\")) or ProcessCommandLine matches regex "([Pp]rogram[Dd]ata|%([Ll]ocal)?[Aa]pp[Dd]ata%|\\\\[Aa]pp[Dd]ata\\\\([Ll]ocal([Ll]ow)?|[Rr]oaming))\\\\[^\\\\]{1,256}$") and (not(((InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\") or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\sdiagnhost.exe" or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\inetsrv\\w3wp.exe"))) and (not(((InitiatingProcessCommandLine contains "JwB7ACIAZgBhAGkAbABlAGQAIgA6AHQAcgB1AGUALAAiAG0AcwBnACIAOgAiAEEAbgBzAGkAYgBsAGUAIAByAGUAcQB1AGkAcgBlAHMAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAdgAzAC4AMAAgAG8AcgAgAG4AZQB3AGUAcgAiAH0AJw" or InitiatingProcessCommandLine contains "cAewAiAGYAYQBpAGwAZQBkACIAOgB0AHIAdQBlACwAIgBtAHMAZwAiADoAIgBBAG4AcwBpAGIAbABlACAAcgBlAHEAdQBpAHIAZQBzACAAUABvAHcAZQByAFMAaABlAGwAbAAgAHYAMwAuADAAIABvAHIAIABuAGUAdwBlAHIAIgB9ACcA" or InitiatingProcessCommandLine contains "nAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnA") or (InitiatingProcessFolderPath in~ ("C:\\ProgramData\\chocolatey\\choco.exe", "C:\\ProgramData\\chocolatey\\tools\\shimgen.exe")) or InitiatingProcessCommandLine contains "\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection")))
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}