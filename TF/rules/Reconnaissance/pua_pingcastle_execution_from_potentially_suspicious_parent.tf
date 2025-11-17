resource "azurerm_sentinel_alert_rule_scheduled" "pua_pingcastle_execution_from_potentially_suspicious_parent" {
  name                       = "pua_pingcastle_execution_from_potentially_suspicious_parent"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - PingCastle Execution From Potentially Suspicious Parent"
  description                = "Detects the execution of PingCastle, a tool designed to quickly assess the Active Directory security level via a script located in a potentially suspicious or uncommon location."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((InitiatingProcessCommandLine contains ".bat" or InitiatingProcessCommandLine contains ".chm" or InitiatingProcessCommandLine contains ".cmd" or InitiatingProcessCommandLine contains ".hta" or InitiatingProcessCommandLine contains ".htm" or InitiatingProcessCommandLine contains ".html" or InitiatingProcessCommandLine contains ".js" or InitiatingProcessCommandLine contains ".lnk" or InitiatingProcessCommandLine contains ".ps1" or InitiatingProcessCommandLine contains ".vbe" or InitiatingProcessCommandLine contains ".vbs" or InitiatingProcessCommandLine contains ".wsf") or (InitiatingProcessCommandLine contains ":\\Perflogs\\" or InitiatingProcessCommandLine contains ":\\Temp\\" or InitiatingProcessCommandLine contains ":\\Users\\Public\\" or InitiatingProcessCommandLine contains ":\\Windows\\Temp\\" or InitiatingProcessCommandLine contains "\\AppData\\Local\\Temp" or InitiatingProcessCommandLine contains "\\AppData\\Roaming\\" or InitiatingProcessCommandLine contains "\\Temporary Internet") or ((InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\Favorites\\") or (InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\Favourites\\") or (InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\Contacts\\"))) and (InitiatingProcessCommandLine contains ".bat" or InitiatingProcessCommandLine contains ".chm" or InitiatingProcessCommandLine contains ".cmd" or InitiatingProcessCommandLine contains ".hta" or InitiatingProcessCommandLine contains ".htm" or InitiatingProcessCommandLine contains ".html" or InitiatingProcessCommandLine contains ".js" or InitiatingProcessCommandLine contains ".lnk" or InitiatingProcessCommandLine contains ".ps1" or InitiatingProcessCommandLine contains ".vbe" or InitiatingProcessCommandLine contains ".vbs" or InitiatingProcessCommandLine contains ".wsf") and (FolderPath endswith "\\PingCastle.exe" or ProcessVersionInfoOriginalFileName =~ "PingCastle.exe" or ProcessVersionInfoProductName =~ "Ping Castle" or (ProcessCommandLine contains "--scanner aclcheck" or ProcessCommandLine contains "--scanner antivirus" or ProcessCommandLine contains "--scanner computerversion" or ProcessCommandLine contains "--scanner foreignusers" or ProcessCommandLine contains "--scanner laps_bitlocker" or ProcessCommandLine contains "--scanner localadmin" or ProcessCommandLine contains "--scanner nullsession" or ProcessCommandLine contains "--scanner nullsession-trust" or ProcessCommandLine contains "--scanner oxidbindings" or ProcessCommandLine contains "--scanner remote" or ProcessCommandLine contains "--scanner share" or ProcessCommandLine contains "--scanner smb" or ProcessCommandLine contains "--scanner smb3querynetwork" or ProcessCommandLine contains "--scanner spooler" or ProcessCommandLine contains "--scanner startup" or ProcessCommandLine contains "--scanner zerologon") or ProcessCommandLine contains "--no-enum-limit" or (ProcessCommandLine contains "--healthcheck" and ProcessCommandLine contains "--level Full") or (ProcessCommandLine contains "--healthcheck" and ProcessCommandLine contains "--server "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Reconnaissance"]
  techniques                 = ["T1595"]
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