resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_execution_of_renamed_sysinternals_tools_registry" {
  name                       = "suspicious_execution_of_renamed_sysinternals_tools_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Execution Of Renamed Sysinternals Tools - Registry"
  description                = "Detects the creation of the \"accepteula\" key related to the Sysinternals tools being created from executables with the wrong name (e.g. a renamed Sysinternals tool) - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where (ActionType =~ "RegistryKeyCreated" and (RegistryKey contains "\\Active Directory Explorer" or RegistryKey contains "\\Handle" or RegistryKey contains "\\LiveKd" or RegistryKey contains "\\ProcDump" or RegistryKey contains "\\Process Explorer" or RegistryKey contains "\\PsExec" or RegistryKey contains "\\PsLoggedon" or RegistryKey contains "\\PsLoglist" or RegistryKey contains "\\PsPasswd" or RegistryKey contains "\\PsPing" or RegistryKey contains "\\PsService" or RegistryKey contains "\\SDelete") and RegistryKey endswith "\\EulaAccepted") and (not((InitiatingProcessFolderPath endswith "\\ADExplorer.exe" or InitiatingProcessFolderPath endswith "\\ADExplorer64.exe" or InitiatingProcessFolderPath endswith "\\handle.exe" or InitiatingProcessFolderPath endswith "\\handle64.exe" or InitiatingProcessFolderPath endswith "\\livekd.exe" or InitiatingProcessFolderPath endswith "\\livekd64.exe" or InitiatingProcessFolderPath endswith "\\procdump.exe" or InitiatingProcessFolderPath endswith "\\procdump64.exe" or InitiatingProcessFolderPath endswith "\\procexp.exe" or InitiatingProcessFolderPath endswith "\\procexp64.exe" or InitiatingProcessFolderPath endswith "\\PsExec.exe" or InitiatingProcessFolderPath endswith "\\PsExec64.exe" or InitiatingProcessFolderPath endswith "\\PsLoggedon.exe" or InitiatingProcessFolderPath endswith "\\PsLoggedon64.exe" or InitiatingProcessFolderPath endswith "\\psloglist.exe" or InitiatingProcessFolderPath endswith "\\psloglist64.exe" or InitiatingProcessFolderPath endswith "\\pspasswd.exe" or InitiatingProcessFolderPath endswith "\\pspasswd64.exe" or InitiatingProcessFolderPath endswith "\\PsPing.exe" or InitiatingProcessFolderPath endswith "\\PsPing64.exe" or InitiatingProcessFolderPath endswith "\\PsService.exe" or InitiatingProcessFolderPath endswith "\\PsService64.exe" or InitiatingProcessFolderPath endswith "\\sdelete.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1588"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}