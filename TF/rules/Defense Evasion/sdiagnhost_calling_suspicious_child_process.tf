resource "azurerm_sentinel_alert_rule_scheduled" "sdiagnhost_calling_suspicious_child_process" {
  name                       = "sdiagnhost_calling_suspicious_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Sdiagnhost Calling Suspicious Child Process"
  description                = "Detects sdiagnhost.exe calling a suspicious child process (e.g. used in exploits for Follina / CVE-2022-30190)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\taskkill.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\calc.exe") and InitiatingProcessFolderPath endswith "\\sdiagnhost.exe") and (not(((ProcessCommandLine contains "bits" and FolderPath endswith "\\cmd.exe") or ((ProcessCommandLine endswith "-noprofile -" or ProcessCommandLine endswith "-noprofile") and FolderPath endswith "\\powershell.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036", "T1218"]
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