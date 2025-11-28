resource "azurerm_sentinel_alert_rule_scheduled" "renamed_schtasks_execution" {
  name                       = "renamed_schtasks_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Renamed Schtasks Execution"
  description                = "Detects the execution of renamed schtasks.exe binary, which is a legitimate Windows utility used for scheduling tasks. One of the very common persistence techniques is schedule malicious tasks using schtasks.exe. Since, it is heavily abused, it is also heavily monitored by security products. To evade detection, threat actors may rename the schtasks.exe binary to schedule their malicious tasks. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((ProcessCommandLine contains " -tn " or ProcessCommandLine contains " /tn " or ProcessCommandLine contains " –tn " or ProcessCommandLine contains " —tn " or ProcessCommandLine contains " ―tn " or ProcessCommandLine contains " -tr " or ProcessCommandLine contains " /tr " or ProcessCommandLine contains " –tr " or ProcessCommandLine contains " —tr " or ProcessCommandLine contains " ―tr " or ProcessCommandLine contains " -sc " or ProcessCommandLine contains " /sc " or ProcessCommandLine contains " –sc " or ProcessCommandLine contains " —sc " or ProcessCommandLine contains " ―sc " or ProcessCommandLine contains " -st " or ProcessCommandLine contains " /st " or ProcessCommandLine contains " –st " or ProcessCommandLine contains " —st " or ProcessCommandLine contains " ―st " or ProcessCommandLine contains " -ru " or ProcessCommandLine contains " /ru " or ProcessCommandLine contains " –ru " or ProcessCommandLine contains " —ru " or ProcessCommandLine contains " ―ru " or ProcessCommandLine contains " -fo " or ProcessCommandLine contains " /fo " or ProcessCommandLine contains " –fo " or ProcessCommandLine contains " —fo " or ProcessCommandLine contains " ―fo ") and (ProcessCommandLine contains " -create " or ProcessCommandLine contains " /create " or ProcessCommandLine contains " –create " or ProcessCommandLine contains " —create " or ProcessCommandLine contains " ―create " or ProcessCommandLine contains " -delete " or ProcessCommandLine contains " /delete " or ProcessCommandLine contains " –delete " or ProcessCommandLine contains " —delete " or ProcessCommandLine contains " ―delete " or ProcessCommandLine contains " -query " or ProcessCommandLine contains " /query " or ProcessCommandLine contains " –query " or ProcessCommandLine contains " —query " or ProcessCommandLine contains " ―query " or ProcessCommandLine contains " -change " or ProcessCommandLine contains " /change " or ProcessCommandLine contains " –change " or ProcessCommandLine contains " —change " or ProcessCommandLine contains " ―change " or ProcessCommandLine contains " -run " or ProcessCommandLine contains " /run " or ProcessCommandLine contains " –run " or ProcessCommandLine contains " —run " or ProcessCommandLine contains " ―run " or ProcessCommandLine contains " -end " or ProcessCommandLine contains " /end " or ProcessCommandLine contains " –end " or ProcessCommandLine contains " —end " or ProcessCommandLine contains " ―end ")) and (not(ProcessCommandLine contains "schtasks"))) or (ProcessVersionInfoOriginalFileName =~ "schtasks.exe" and (not(FolderPath endswith "\\schtasks.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "Persistence", "PrivilegeEscalation"]
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