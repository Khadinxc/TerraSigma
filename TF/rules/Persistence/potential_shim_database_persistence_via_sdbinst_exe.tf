resource "azurerm_sentinel_alert_rule_scheduled" "potential_shim_database_persistence_via_sdbinst_exe" {
  name                       = "potential_shim_database_persistence_via_sdbinst_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Shim Database Persistence via Sdbinst.EXE"
  description                = "Detects installation of a new shim using sdbinst.exe. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".sdb" and (FolderPath endswith "\\sdbinst.exe" or ProcessVersionInfoOriginalFileName =~ "sdbinst.exe")) and (not(((ProcessCommandLine contains ":\\Program Files (x86)\\IIS Express\\iisexpressshim.sdb" or ProcessCommandLine contains ":\\Program Files\\IIS Express\\iisexpressshim.sdb") and InitiatingProcessFolderPath endswith "\\msiexec.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1546"]
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