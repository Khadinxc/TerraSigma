resource "azurerm_sentinel_alert_rule_scheduled" "legitimate_application_writing_files_in_uncommon_location" {
  name                       = "legitimate_application_writing_files_in_uncommon_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Legitimate Application Writing Files In Uncommon Location"
  description                = "Detects legitimate applications writing any type of file to uncommon or suspicious locations that are not typical for application data storage or execution. Adversaries may leverage legitimate applications (Living off the Land Binaries - LOLBins) to drop or download malicious files to uncommon locations on the system to evade detection by security solutions."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\eqnedt32.exe" or InitiatingProcessFolderPath endswith "\\wordpad.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe" or InitiatingProcessFolderPath endswith "\\cmdl32.exe" or InitiatingProcessFolderPath endswith "\\certutil.exe" or InitiatingProcessFolderPath endswith "\\certoc.exe" or InitiatingProcessFolderPath endswith "\\CertReq.exe" or InitiatingProcessFolderPath endswith "\\bitsadmin.exe" or InitiatingProcessFolderPath endswith "\\Desktopimgdownldr.exe" or InitiatingProcessFolderPath endswith "\\esentutl.exe" or InitiatingProcessFolderPath endswith "\\expand.exe" or InitiatingProcessFolderPath endswith "\\extrac32.exe" or InitiatingProcessFolderPath endswith "\\replace.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\ftp.exe" or InitiatingProcessFolderPath endswith "\\Ldifde.exe" or InitiatingProcessFolderPath endswith "\\RdrCEF.exe" or InitiatingProcessFolderPath endswith "\\hh.exe" or InitiatingProcessFolderPath endswith "\\finger.exe" or InitiatingProcessFolderPath endswith "\\findstr.exe") and (FolderPath contains ":\\Perflogs" or FolderPath contains ":\\ProgramData\\" or FolderPath contains ":\\Temp\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains ":\\Windows\\" or FolderPath contains "\\$Recycle.Bin\\" or FolderPath contains "\\AppData\\Local\\" or FolderPath contains "\\AppData\\Roaming\\" or FolderPath contains "\\Contacts\\" or FolderPath contains "\\Desktop\\" or FolderPath contains "\\Favorites\\" or FolderPath contains "\\Favourites\\" or FolderPath contains "\\inetpub\\wwwroot\\" or FolderPath contains "\\Music\\" or FolderPath contains "\\Pictures\\" or FolderPath contains "\\Start Menu\\Programs\\Startup\\" or FolderPath contains "\\Users\\Default\\" or FolderPath contains "\\Videos\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1218", "T1105"]
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