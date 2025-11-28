resource "azurerm_sentinel_alert_rule_scheduled" "potential_initial_access_via_dll_search_order_hijacking" {
  name                       = "potential_initial_access_via_dll_search_order_hijacking"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Initial Access via DLL Search Order Hijacking"
  description                = "Detects attempts to create a DLL file to a known desktop application dependencies folder such as Slack, Teams or OneDrive and by an unusual process. This may indicate an attempt to load a malicious module via DLL search order hijacking."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\MSACCESS.EXE" or InitiatingProcessFolderPath endswith "\\MSPUB.EXE" or InitiatingProcessFolderPath endswith "\\fltldr.exe" or InitiatingProcessFolderPath endswith "\\cmd.exe" or InitiatingProcessFolderPath endswith "\\certutil.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe" or InitiatingProcessFolderPath endswith "\\curl.exe" or InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe") and (FolderPath contains "\\Microsoft\\OneDrive\\" or FolderPath contains "\\Microsoft OneDrive\\" or FolderPath contains "\\Microsoft\\Teams\\" or FolderPath contains "\\Local\\slack\\app-" or FolderPath contains "\\Local\\Programs\\Microsoft VS Code\\") and (FolderPath contains "\\Users\\" and FolderPath contains "\\AppData\\") and FolderPath endswith ".dll") and (not((InitiatingProcessFolderPath endswith "\\cmd.exe" and (FolderPath contains "\\Users\\" and FolderPath contains "\\AppData\\" and FolderPath contains "\\Microsoft\\OneDrive\\" and FolderPath contains "\\api-ms-win-core-"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "InitialAccess", "DefenseEvasion"]
  techniques                 = ["T1566", "T1574"]
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