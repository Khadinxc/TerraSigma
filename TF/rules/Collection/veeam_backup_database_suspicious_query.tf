resource "azurerm_sentinel_alert_rule_scheduled" "veeam_backup_database_suspicious_query" {
  name                       = "veeam_backup_database_suspicious_query"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Veeam Backup Database Suspicious Query"
  description                = "Detects potentially suspicious SQL queries using SQLCmd targeting the Veeam backup databases in order to steal information."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "BackupRepositories" or ProcessCommandLine contains "Backups" or ProcessCommandLine contains "Credentials" or ProcessCommandLine contains "HostCreds" or ProcessCommandLine contains "SmbFileShares" or ProcessCommandLine contains "Ssh_creds" or ProcessCommandLine contains "VSphereInfo") and ((ProcessCommandLine contains "VeeamBackup" and ProcessCommandLine contains "From ") and FolderPath endswith "\\sqlcmd.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1005"]
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