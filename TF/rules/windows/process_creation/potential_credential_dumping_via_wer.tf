resource "azurerm_sentinel_alert_rule_scheduled" "potential_credential_dumping_via_wer" {
  name                       = "potential_credential_dumping_via_wer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Credential Dumping Via WER"
  description                = "Detects potential credential dumping via Windows Error Reporting LSASS Shtinkering technique which uses the Windows Error Reporting to dump lsass - Windows Error Reporting might produce similar behavior. In that case, check the PID associated with the \"-p\" parameter in the CommandLine."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains " -u -p " and ProcessCommandLine contains " -ip " and ProcessCommandLine contains " -s ") and (InitiatingProcessAccountName contains "AUTHORI" or InitiatingProcessAccountName contains "AUTORI") and (AccountName contains "AUTHORI" or AccountName contains "AUTORI")) and (FolderPath endswith "\\Werfault.exe" or ProcessVersionInfoOriginalFileName =~ "WerFault.exe")) and (not(InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\lsass.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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