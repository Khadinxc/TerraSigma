resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_python_shell_os_system" {
  name                       = "proc_creation_lnx_python_shell_os_system"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Inline Python Execution - Spawn Shell Via OS System Library"
  description                = <<DESC
    Detects execution of inline Python code via the "-c" in order to call the "system" function from the "os" library, and spawn a shell.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_python_shell_os_system.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "/bin/bash" or ProcessCommandLine contains "/bin/dash" or ProcessCommandLine contains "/bin/fish" or ProcessCommandLine contains "/bin/sh" or ProcessCommandLine contains "/bin/zsh") and (ProcessCommandLine contains " -c " and ProcessCommandLine contains "os.system(")) and ((FolderPath endswith "/python" or FolderPath endswith "/python2" or FolderPath endswith "/python3") or (FolderPath contains "/python2." or FolderPath contains "/python3."))
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