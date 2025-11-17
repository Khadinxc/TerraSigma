resource "azurerm_sentinel_alert_rule_scheduled" "conhost_spawned_by_uncommon_parent_process" {
  name                       = "conhost_spawned_by_uncommon_parent_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Conhost Spawned By Uncommon Parent Process"
  description                = "Detects when the Console Window Host (conhost.exe) process is spawned by an uncommon parent process, which could be indicative of potential code injection activity."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\conhost.exe" and (InitiatingProcessFolderPath endswith "\\explorer.exe" or InitiatingProcessFolderPath endswith "\\lsass.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\services.exe" or InitiatingProcessFolderPath endswith "\\smss.exe" or InitiatingProcessFolderPath endswith "\\spoolsv.exe" or InitiatingProcessFolderPath endswith "\\svchost.exe" or InitiatingProcessFolderPath endswith "\\userinit.exe" or InitiatingProcessFolderPath endswith "\\wininit.exe" or InitiatingProcessFolderPath endswith "\\winlogon.exe")) and (not((InitiatingProcessCommandLine contains "-k apphost -s AppHostSvc" or InitiatingProcessCommandLine contains "-k imgsvc" or InitiatingProcessCommandLine contains "-k localService -p -s RemoteRegistry" or InitiatingProcessCommandLine contains "-k LocalSystemNetworkRestricted -p -s NgcSvc" or InitiatingProcessCommandLine contains "-k NetSvcs -p -s NcaSvc" or InitiatingProcessCommandLine contains "-k netsvcs -p -s NetSetupSvc" or InitiatingProcessCommandLine contains "-k netsvcs -p -s wlidsvc" or InitiatingProcessCommandLine contains "-k NetworkService -p -s DoSvc" or InitiatingProcessCommandLine contains "-k wsappx -p -s AppXSvc" or InitiatingProcessCommandLine contains "-k wsappx -p -s ClipSVC" or InitiatingProcessCommandLine contains "-k wusvcs -p -s WaaSMedicSvc"))) and (not((InitiatingProcessCommandLine contains "C:\\Program Files (x86)\\Dropbox\\Client\\" or InitiatingProcessCommandLine contains "C:\\Program Files\\Dropbox\\Client\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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