resource "azurerm_sentinel_alert_rule_scheduled" "copying_sensitive_files_with_credential_data" {
  name                       = "copying_sensitive_files_with_credential_data"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Copying Sensitive Files with Credential Data"
  description                = "Files with well-known filenames (sensitive files with credential data) copying - Copying sensitive files for legitimate use (eg. backup) or forensic investigation by legitimate incident responder or forensic investigator."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "vss" or ProcessCommandLine contains " -m " or ProcessCommandLine contains " /m " or ProcessCommandLine contains " –m " or ProcessCommandLine contains " —m " or ProcessCommandLine contains " ―m " or ProcessCommandLine contains " -y " or ProcessCommandLine contains " /y " or ProcessCommandLine contains " –y " or ProcessCommandLine contains " —y " or ProcessCommandLine contains " ―y ") and (FolderPath endswith "\\esentutl.exe" or ProcessVersionInfoOriginalFileName =~ "\\esentutl.exe")) or (ProcessCommandLine contains "\\config\\RegBack\\sam" or ProcessCommandLine contains "\\config\\RegBack\\security" or ProcessCommandLine contains "\\config\\RegBack\\system" or ProcessCommandLine contains "\\config\\sam" or ProcessCommandLine contains "\\config\\security" or ProcessCommandLine contains "\\config\\system " or ProcessCommandLine contains "\\repair\\sam" or ProcessCommandLine contains "\\repair\\security" or ProcessCommandLine contains "\\repair\\system" or ProcessCommandLine contains "\\windows\\ntds\\ntds.dit")
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