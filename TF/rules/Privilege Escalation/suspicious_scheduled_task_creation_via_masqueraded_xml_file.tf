resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_scheduled_task_creation_via_masqueraded_xml_file" {
  name                       = "suspicious_scheduled_task_creation_via_masqueraded_xml_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Scheduled Task Creation via Masqueraded XML File"
  description                = "Detects the creation of a scheduled task using the \"-XML\" flag with a file without the '.xml' extension. This behavior could be indicative of potential defense evasion attempt during persistence"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "/create" or ProcessCommandLine contains "-create") and (ProcessCommandLine contains "/xml" or ProcessCommandLine contains "-xml") and (FolderPath endswith "\\schtasks.exe" or ProcessVersionInfoOriginalFileName =~ "schtasks.exe")) and (not((ProcessCommandLine contains ".xml" or ((InitiatingProcessCommandLine contains ":\\WINDOWS\\Installer\\MSI" and InitiatingProcessCommandLine contains ".tmp,zzzzInvokeManagedCustomActionOutOfProc") and InitiatingProcessFolderPath endswith "\\rundll32.exe") or (ProcessIntegrityLevel in~ ("System", "S-1-16-16384"))))) and (not(((InitiatingProcessFolderPath contains ":\\ProgramData\\OEM\\UpgradeTool\\CareCenter_" and InitiatingProcessFolderPath contains "\\BUnzip\\Setup_msi.exe") or InitiatingProcessFolderPath endswith ":\\Program Files\\Axis Communications\\AXIS Camera Station\\SetupActions.exe" or InitiatingProcessFolderPath endswith ":\\Program Files\\Axis Communications\\AXIS Device Manager\\AdmSetupActions.exe" or InitiatingProcessFolderPath endswith ":\\Program Files (x86)\\Zemana\\AntiMalware\\AntiMalware.exe" or InitiatingProcessFolderPath endswith ":\\Program Files\\Dell\\SupportAssist\\pcdrcui.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "DefenseEvasion", "Persistence"]
  techniques                 = ["T1036", "T1053"]
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