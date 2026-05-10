resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_chmod_targeting_sensitive_directories" {
  name                       = "proc_creation_lnx_chmod_targeting_sensitive_directories"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Chmod Targeting Sensitive Directories"
  description                = <<DESC
    Detects chmod targeting files in sensitive directory paths on Linux systems. Attackers may use chmod to change permissions of files in these directories to maintain persistence, escalate privileges, or disrupt system operations.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_chmod_targeting_sensitive_directories.yml

    False Positives:
    - Some false positives are to be expected. Apply additional filters as needed before pushing to production.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "/tmp/" or ProcessCommandLine contains "/.Library/" or ProcessCommandLine contains "/etc/" or ProcessCommandLine contains "/opt/") and FolderPath endswith "/chmod") and (not((ProcessCommandLine startswith "chmod 700 /tmp/apt-key-gpghome." or ProcessCommandLine =~ "chmod 0775 /etc/landscape/" or ProcessCommandLine startswith "chmod 755 /var/tmp/mkinitramfs" or (ProcessCommandLine contains "/etc/" and (InitiatingProcessCommandLine contains "/var/lib/dpkg/info/" and InitiatingProcessCommandLine contains ".postinst configure")) or ProcessCommandLine =~ "chmod 644 /etc/apparmor.d/tunables/home.d/ubuntu" or (ProcessCommandLine contains "chmod --reference=/etc/shells" and InitiatingProcessCommandLine endswith "/update-shells"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  techniques                 = ["T1222"]
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