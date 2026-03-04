resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_werfaultsecure_abuse" {
  name                       = "proc_creation_win_werfaultsecure_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PPL Tampering Via WerFaultSecure"
  description                = "Detects potential abuse of WerFaultSecure.exe to dump Protected Process Light (PPL) processes like LSASS or to freeze security solutions (EDR/antivirus). This technique is used by tools such as EDR-Freeze and WSASS to bypass PPL protections and access sensitive information or disable security software. Distinct command line patterns help identify the specific tool: - WSASS usage typically shows: \"WSASS.exe WerFaultSecure.exe [PID]\" in ParentCommandLine - EDR-Freeze usage typically shows: \"EDR-Freeze_[version].exe [PID] [timeout]\" in ParentCommandLine Legitimate debugging operations using WerFaultSecure are rare in production environments and should be investigated. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_werfaultsecure_abuse.yml - Legitimate usage of WerFaultSecure for debugging purposes | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_werfaultsecure_abuse.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /h " and ProcessCommandLine contains " /pid " and ProcessCommandLine contains " /tid " and ProcessCommandLine contains " /encfile " and ProcessCommandLine contains " /cancel " and ProcessCommandLine contains " /type " and ProcessCommandLine contains " 268310") and (FolderPath endswith "\\WerFaultSecure.exe" or ProcessVersionInfoOriginalFileName =~ "WerFaultSecure.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1562", "T1003"]
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