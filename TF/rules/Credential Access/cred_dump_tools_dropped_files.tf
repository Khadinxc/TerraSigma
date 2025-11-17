resource "azurerm_sentinel_alert_rule_scheduled" "cred_dump_tools_dropped_files" {
  name                       = "cred_dump_tools_dropped_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Cred Dump Tools Dropped Files"
  description                = "Files with well-known filenames (parts of credential dump software or files produced by them) creation - Legitimate Administrator using tool for password recovery"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\fgdump-log" or FolderPath contains "\\kirbi" or FolderPath contains "\\pwdump" or FolderPath contains "\\pwhashes" or FolderPath contains "\\wce_ccache" or FolderPath contains "\\wce_krbtkts") or (FolderPath endswith "\\cachedump.exe" or FolderPath endswith "\\cachedump64.exe" or FolderPath endswith "\\DumpExt.dll" or FolderPath endswith "\\DumpSvc.exe" or FolderPath endswith "\\Dumpy.exe" or FolderPath endswith "\\fgexec.exe" or FolderPath endswith "\\lsremora.dll" or FolderPath endswith "\\lsremora64.dll" or FolderPath endswith "\\NTDS.out" or FolderPath endswith "\\procdump64.exe" or FolderPath endswith "\\pstgdump.exe" or FolderPath endswith "\\pwdump.exe" or FolderPath endswith "\\SAM.out" or FolderPath endswith "\\SECURITY.out" or FolderPath endswith "\\servpw.exe" or FolderPath endswith "\\servpw64.exe" or FolderPath endswith "\\SYSTEM.out" or FolderPath endswith "\\test.pwd" or FolderPath endswith "\\wceaux.dll")
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}