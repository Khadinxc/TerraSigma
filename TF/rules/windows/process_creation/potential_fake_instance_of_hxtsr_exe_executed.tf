resource "azurerm_sentinel_alert_rule_scheduled" "potential_fake_instance_of_hxtsr_exe_executed" {
  name                       = "potential_fake_instance_of_hxtsr_exe_executed"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Fake Instance Of Hxtsr.EXE Executed"
  description                = "HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications. HxTsr.exe is part of Outlook apps, because it resides in a hidden \"WindowsApps\" subfolder of \"C:\\Program Files\". Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\hxtsr.exe" and (not((FolderPath contains ":\\program files\\windowsapps\\microsoft.windowscommunicationsapps_" and FolderPath endswith "\\hxtsr.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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