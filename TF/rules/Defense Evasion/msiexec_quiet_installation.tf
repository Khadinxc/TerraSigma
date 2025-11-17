resource "azurerm_sentinel_alert_rule_scheduled" "msiexec_quiet_installation" {
  name                       = "msiexec_quiet_installation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Msiexec Quiet Installation"
  description                = "Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi) - WindowsApps installing updates via the quiet flag"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-i" or ProcessCommandLine contains "/i" or ProcessCommandLine contains "–i" or ProcessCommandLine contains "—i" or ProcessCommandLine contains "―i" or ProcessCommandLine contains "-package" or ProcessCommandLine contains "/package" or ProcessCommandLine contains "–package" or ProcessCommandLine contains "—package" or ProcessCommandLine contains "―package" or ProcessCommandLine contains "-a" or ProcessCommandLine contains "/a" or ProcessCommandLine contains "–a" or ProcessCommandLine contains "—a" or ProcessCommandLine contains "―a" or ProcessCommandLine contains "-j" or ProcessCommandLine contains "/j" or ProcessCommandLine contains "–j" or ProcessCommandLine contains "—j" or ProcessCommandLine contains "―j") and (FolderPath endswith "\\msiexec.exe" or ProcessVersionInfoOriginalFileName =~ "msiexec.exe") and (ProcessCommandLine contains "-q" or ProcessCommandLine contains "/q" or ProcessCommandLine contains "–q" or ProcessCommandLine contains "—q" or ProcessCommandLine contains "―q")) and (not((((ProcessIntegrityLevel in~ ("System", "S-1-16-16384")) and InitiatingProcessFolderPath =~ "C:\\Windows\\CCM\\Ccm32BitLauncher.exe") or InitiatingProcessFolderPath startswith "C:\\Windows\\Temp\\" or (InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" and InitiatingProcessFolderPath startswith "C:\\Users\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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