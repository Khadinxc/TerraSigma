resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_celery_worker_shell_spawn" {
  name                       = "proc_creation_lnx_celery_worker_shell_spawn"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell Spawned by Celery Worker Process"
  description                = <<DESC
    Detects a system shell interpreter being spawned directly by a Celery worker process. This behavior indicates a Python background task execution framework is evaluating raw string input through a shell execution context, which is highly indicative of successful command or prompt injection exploitation against an LLM agent task.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_celery_worker_shell_spawn.yml

    False Positives:
    - Legacy or custom administrative tasks deliberately hardcoded with shell=True or os.system execution inside Celery task functions.
    - Media processing, deployment, or reporting pipelines that intentionally shell out to external tools (e.g. ffmpeg, git) from within a task.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "/ash" or FolderPath endswith "/bash" or FolderPath endswith "/busybox" or FolderPath endswith "/csh" or FolderPath endswith "/dash" or FolderPath endswith "/fish" or FolderPath endswith "/ksh" or FolderPath endswith "/sh" or FolderPath endswith "/tcsh" or FolderPath endswith "/zsh") and InitiatingProcessCommandLine contains "celery") and ((InitiatingProcessFolderPath endswith "/python" or InitiatingProcessFolderPath endswith "/python3") or InitiatingProcessFolderPath contains "/python3.")
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