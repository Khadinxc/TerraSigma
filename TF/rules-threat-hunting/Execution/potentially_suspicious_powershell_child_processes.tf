resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_powershell_child_processes" {
  name                       = "potentially_suspicious_powershell_child_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious PowerShell Child Processes"
  description                = "Detects potentially suspicious child processes spawned by PowerShell. Use this rule to hunt for potential anomalies initiating from PowerShell scripts and commands."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\bash.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\hh.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\scrcons.exe" or FolderPath endswith "\\scriptrunner.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe") and (InitiatingProcessFolderPath endswith "\\powershell_ise.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe")) and (not(((ProcessCommandLine contains "-verifystore " and FolderPath endswith "\\certutil.exe") or ((ProcessCommandLine contains "qfe list" or ProcessCommandLine contains "diskdrive " or ProcessCommandLine contains "csproduct " or ProcessCommandLine contains "computersystem " or ProcessCommandLine contains " os " or ProcessCommandLine startswith "") and FolderPath endswith "\\wmic.exe")))) and (not((ProcessCommandLine contains "\\Program Files\\Amazon\\WorkspacesConfig\\Scripts\\" and InitiatingProcessCommandLine contains "\\Program Files\\Amazon\\WorkspacesConfig\\Scripts\\")))
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