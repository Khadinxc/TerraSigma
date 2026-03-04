resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_macos_schedule_task_job_cron" {
  name                       = "proc_creation_macos_schedule_task_job_cron"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scheduled Cron Task/Job - MacOs"
  description                = "Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_schedule_task_job_cron.yml - Legitimate administration activities | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_schedule_task_job_cron.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "/tmp/" and FolderPath endswith "/crontab"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1053"]
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