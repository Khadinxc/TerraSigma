resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_certreq_download" {
  name                       = "proc_creation_win_certreq_download"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious CertReq Command to Download"
  description                = "Detects a suspicious CertReq execution downloading a file. This behavior is often used by attackers to download additional payloads or configuration files. Certreq is a built-in Windows utility used to request and retrieve certificates from a certification authority (CA). However, it can be abused by threat actors for malicious purposes. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certreq_download.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certreq_download.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-config" or ProcessCommandLine contains "/config" or ProcessCommandLine contains "–config" or ProcessCommandLine contains "—config" or ProcessCommandLine contains "―config") and (ProcessCommandLine contains "-Post" or ProcessCommandLine contains "/Post" or ProcessCommandLine contains "–Post" or ProcessCommandLine contains "—Post" or ProcessCommandLine contains "―Post") and ProcessCommandLine contains "http" and (FolderPath endswith "\\certreq.exe" or ProcessVersionInfoOriginalFileName =~ "CertReq.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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