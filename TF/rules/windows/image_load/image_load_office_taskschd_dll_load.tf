resource "azurerm_sentinel_alert_rule_scheduled" "image_load_office_taskschd_dll_load" {
  name                       = "image_load_office_taskschd_dll_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Microsoft Office Application Loading Task Scheduler DLL"
  description                = <<DESC
    Detects a Microsoft Office application loading taskschd.dll, which exposes COM interfaces for managing Windows Scheduled Tasks. This load is an early precursor to scheduled task creation or modification and has been frequently observed in macro-enabled malicious documents attempting to establish persistence.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_office_taskschd_dll_load.yml

    False Positives:
    - Legitimate add-ins or automation scripts that use Office applications to manage scheduled tasks (rare in most environments)
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\taskschd.dll" or InitiatingProcessVersionInfoOriginalFileName =~ "taskschd.dll") and (InitiatingProcessFolderPath endswith "\\eqnedt32.exe" or InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\fltldr.exe" or InitiatingProcessFolderPath endswith "\\graph.exe" or InitiatingProcessFolderPath endswith "\\msaccess.exe" or InitiatingProcessFolderPath endswith "\\mspub.exe" or InitiatingProcessFolderPath endswith "\\onenote.exe" or InitiatingProcessFolderPath endswith "\\onenoteim.exe" or InitiatingProcessFolderPath endswith "\\onenotem.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\visio.exe" or InitiatingProcessFolderPath endswith "\\winproj.exe" or InitiatingProcessFolderPath endswith "\\winword.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "Execution"]
  techniques                 = ["T1053", "T1204"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}