resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner" {
  name                       = "proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Script Interpreter Spawning Credential Scanner - Linux"
  description                = <<DESC
    Detects a script interpreter process (like node.js or bun) spawning a known credential scanning tool (e.g., trufflehog, gitleaks). This behavior is indicative of an attempt to find and steal secrets, as seen in the "Shai-Hulud: The Second Coming" campaign.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_script_interpretor_spawn_credential_scanner.yml

    False Positives:
    - Legitimate pre-commit hooks or CI/CD pipeline jobs that use a script to run a credential scanner as part of a security check.
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "/trufflehog" or FolderPath endswith "/gitleaks") or (ProcessCommandLine contains "trufflehog" or ProcessCommandLine contains "gitleaks")) and (InitiatingProcessFolderPath endswith "/node" or InitiatingProcessFolderPath endswith "/bun")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess", "Execution", "Collection"]
  techniques                 = ["T1552", "T1005", "T1059"]
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