resource "azurerm_sentinel_alert_rule_scheduled" "enumeration_for_3rd_party_creds_from_cli" {
  name                       = "enumeration_for_3rd_party_creds_from_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Enumeration for 3rd Party Creds From CLI"
  description                = "Detects processes that query known 3rd party registry keys that holds credentials via commandline"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\Software\\Aerofox\\Foxmail\\V3.1" or ProcessCommandLine contains "\\Software\\Aerofox\\FoxmailPreview" or ProcessCommandLine contains "\\Software\\DownloadManager\\Passwords" or ProcessCommandLine contains "\\Software\\FTPWare\\COREFTP\\Sites" or ProcessCommandLine contains "\\Software\\IncrediMail\\Identities" or ProcessCommandLine contains "\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" or ProcessCommandLine contains "\\Software\\Mobatek\\MobaXterm\\" or ProcessCommandLine contains "\\Software\\OpenSSH\\Agent\\Keys" or ProcessCommandLine contains "\\Software\\OpenVPN-GUI\\configs" or ProcessCommandLine contains "\\Software\\ORL\\WinVNC3\\Password" or ProcessCommandLine contains "\\Software\\Qualcomm\\Eudora\\CommandLine" or ProcessCommandLine contains "\\Software\\RealVNC\\WinVNC4" or ProcessCommandLine contains "\\Software\\RimArts\\B2\\Settings" or ProcessCommandLine contains "\\Software\\SimonTatham\\PuTTY\\Sessions" or ProcessCommandLine contains "\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\" or ProcessCommandLine contains "\\Software\\Sota\\FFFTP" or ProcessCommandLine contains "\\Software\\TightVNC\\Server" or ProcessCommandLine contains "\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin") and (not(((ProcessCommandLine contains "export" or ProcessCommandLine contains "save") and FolderPath endswith "reg.exe")))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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