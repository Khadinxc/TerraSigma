resource "azurerm_sentinel_alert_rule_scheduled" "unc4841_download_tar_file_from_untrusted_direct_ip_via_wget" {
  name                       = "unc4841_download_tar_file_from_untrusted_direct_ip_via_wget"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UNC4841 - Download Tar File From Untrusted Direct IP Via Wget"
  description                = "Detects execution of \"wget\" to download a \"tar\" from an IP address that doesn't have a trusted certificate. As seen used by UNC4841 during their Barracuda ESG zero day exploitation."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--no-check-certificate" and ProcessCommandLine endswith ".tar" and ProcessCommandLine matches regex "https://[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" and FolderPath endswith "/wget") and (not((ProcessCommandLine contains "https://10." or ProcessCommandLine contains "https://192.168." or ProcessCommandLine contains "https://172.16." or ProcessCommandLine contains "https://172.17." or ProcessCommandLine contains "https://172.18." or ProcessCommandLine contains "https://172.19." or ProcessCommandLine contains "https://172.20." or ProcessCommandLine contains "https://172.21." or ProcessCommandLine contains "https://172.22." or ProcessCommandLine contains "https://172.23." or ProcessCommandLine contains "https://172.24." or ProcessCommandLine contains "https://172.25." or ProcessCommandLine contains "https://172.26." or ProcessCommandLine contains "https://172.27." or ProcessCommandLine contains "https://172.28." or ProcessCommandLine contains "https://172.29." or ProcessCommandLine contains "https://172.30." or ProcessCommandLine contains "https://172.31." or ProcessCommandLine contains "https://127." or ProcessCommandLine contains "https://169.254.")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1140"]
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