resource "azurerm_sentinel_alert_rule_scheduled" "registry_export_of_third_party_credentials" {
  name                       = "registry_export_of_third_party_credentials"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Export of Third-Party Credentials"
  description                = "Detects the use of reg.exe to export registry paths associated with third-party credentials. Credential stealers have been known to use this technique to extract sensitive information from the registry."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\Software\\Aerofox\\Foxmail\\V3.1" or ProcessCommandLine contains "\\Software\\Aerofox\\FoxmailPreview" or ProcessCommandLine contains "\\Software\\DownloadManager\\Passwords" or ProcessCommandLine contains "\\Software\\FTPWare\\COREFTP\\Sites" or ProcessCommandLine contains "\\Software\\IncrediMail\\Identities" or ProcessCommandLine contains "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" or ProcessCommandLine contains "\\Software\\Mobatek\\MobaXterm" or ProcessCommandLine contains "\\Software\\OpenSSH\\Agent\\Keys" or ProcessCommandLine contains "\\Software\\OpenVPN-GUI\\configs" or ProcessCommandLine contains "\\Software\\ORL\\WinVNC3\\Password" or ProcessCommandLine contains "\\Software\\Qualcomm\\Eudora\\CommandLine" or ProcessCommandLine contains "\\Software\\RealVNC\\WinVNC4" or ProcessCommandLine contains "\\Software\\RimArts\\B2\\Settings" or ProcessCommandLine contains "\\Software\\SimonTatham\\PuTTY\\Sessions" or ProcessCommandLine contains "\\Software\\SimonTatham\\PuTTY\\SshHostKeys" or ProcessCommandLine contains "\\Software\\Sota\\FFFTP" or ProcessCommandLine contains "\\Software\\TightVNC\\Server" or ProcessCommandLine contains "\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin") and (ProcessCommandLine contains "save" or ProcessCommandLine contains "export") and (FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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