resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_systemsettingsadminflows_defender_disable" {
  name                       = "proc_creation_win_systemsettingsadminflows_defender_disable"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Defender Disabled Via SystemSettingsAdminFlows.EXE"
  description                = <<DESC
    Detects the usage of SystemSettingsAdminFlows.exe to disable Windows Defender. SystemSettingsAdminFlows.exe is a legitimate Windows component used for administrative configuration tasks. However, attackers may abuse it to disable Windows Defender as part of their attack chain, especially in the context of ransomware or other malware campaigns.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_systemsettingsadminflows_defender_disable.yml

    False Positives:
    - Legitimate turn off of Windows Defender by the technical users or administrators for troubleshooting or other purposes.
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "defender" and (FolderPath endswith "\\SystemSettingsAdminFlows.exe" or ProcessVersionInfoOriginalFileName =~ "SystemSettingsAdminFlows.EXE")) and (((ProcessCommandLine contains "RTP " or ProcessCommandLine contains "RealTimeProtection " or ProcessCommandLine contains "DisableEnhancedNotifications ") and ProcessCommandLine contains "1") or ((ProcessCommandLine contains "SubmitSamplesConsent " or ProcessCommandLine contains "SpyNetReporting " or ProcessCommandLine contains "DisableCDPUserAuthPolicy ") and ProcessCommandLine contains "0"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  techniques                 = ["T1685"]
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