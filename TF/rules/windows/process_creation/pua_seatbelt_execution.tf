resource "azurerm_sentinel_alert_rule_scheduled" "pua_seatbelt_execution" {
  name                       = "pua_seatbelt_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Seatbelt Execution"
  description                = "Detects the execution of the PUA/Recon tool Seatbelt via PE information of command line parameters - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\Seatbelt.exe" or ProcessVersionInfoOriginalFileName =~ "Seatbelt.exe" or ProcessVersionInfoFileDescription =~ "Seatbelt" or (ProcessCommandLine contains " DpapiMasterKeys" or ProcessCommandLine contains " InterestingProcesses" or ProcessCommandLine contains " InterestingFiles" or ProcessCommandLine contains " CertificateThumbprints" or ProcessCommandLine contains " ChromiumBookmarks" or ProcessCommandLine contains " ChromiumHistory" or ProcessCommandLine contains " ChromiumPresence" or ProcessCommandLine contains " CloudCredentials" or ProcessCommandLine contains " CredEnum" or ProcessCommandLine contains " CredGuard" or ProcessCommandLine contains " FirefoxHistory" or ProcessCommandLine contains " ProcessCreationEvents")) or ((ProcessCommandLine contains " -group=misc" or ProcessCommandLine contains " -group=remote" or ProcessCommandLine contains " -group=chromium" or ProcessCommandLine contains " -group=slack" or ProcessCommandLine contains " -group=system" or ProcessCommandLine contains " -group=user" or ProcessCommandLine contains " -group=all") and ProcessCommandLine contains " -outputfile=")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1526", "T1087", "T1083"]
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