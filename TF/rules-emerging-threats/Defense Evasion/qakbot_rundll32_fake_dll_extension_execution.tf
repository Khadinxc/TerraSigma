resource "azurerm_sentinel_alert_rule_scheduled" "qakbot_rundll32_fake_dll_extension_execution" {
  name                       = "qakbot_rundll32_fake_dll_extension_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Qakbot Rundll32 Fake DLL Extension Execution"
  description                = "Detects specific process tree behavior of a \"rundll32\" execution where the DLL doesn't have the \".dll\" extension. This is often linked with potential Qakbot activity. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains ":\\ProgramData\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\AppData\\Roaming\\") and FolderPath endswith "\\rundll32.exe" and (InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\curl.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe")) and (not(ProcessCommandLine contains ".dll"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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