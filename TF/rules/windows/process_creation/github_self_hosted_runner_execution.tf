resource "azurerm_sentinel_alert_rule_scheduled" "github_self_hosted_runner_execution" {
  name                       = "github_self_hosted_runner_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Github Self-Hosted Runner Execution"
  description                = "Detects GitHub self-hosted runners executing workflows on local infrastructure that could be abused for persistence and code execution. Shai-Hulud is an npm supply chain worm targeting CI/CD environments. It installs runners on compromised systems to maintain access after credential theft, leveraging their access to secrets and internal networks. - Legitimate GitHub self-hosted runner installations on designated CI/CD infrastructure - Authorized runner deployments by DevOps/Platform teams following change management - Scheduled runner updates or reconfigurations on existing build agents - Self-hosted runners that follow expected/known naming patterns - Installation via expected/known configuration management tools (reflected mostly as parent process name)"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "spawnclient" and (FolderPath endswith "\\Runner.Worker.exe" or ProcessVersionInfoOriginalFileName =~ "Runner.Worker.dll")) or ((ProcessCommandLine contains "run" or ProcessCommandLine contains "configure") and (FolderPath endswith "\\Runner.Listener.exe" or ProcessVersionInfoOriginalFileName =~ "Runner.Listener.dll"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1102", "T1071"]
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