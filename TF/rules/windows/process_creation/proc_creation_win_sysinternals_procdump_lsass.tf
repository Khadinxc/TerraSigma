resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_sysinternals_procdump_lsass" {
  name                       = "proc_creation_win_sysinternals_procdump_lsass"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential LSASS Process Dump Via Procdump"
  description                = <<DESC
    Detects potential credential harvesting attempts through LSASS memory dumps using ProcDump. This rule identifies suspicious command-line patterns that combine memory dump flags (-ma, -mm, -mp) with LSASS-related process markers. LSASS (Local Security Authority Subsystem Service) contains sensitive authentication data including plaintext passwords, NTLM hashes, and Kerberos tickets in memory. Attackers commonly dump LSASS memory to extract credentials for lateral movement and privilege escalation.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml

    False Positives:
    - Unlikely, because no one should dump an lsass process memory
    - Another tool that uses command line flags similar to ProcDump
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -ma " or ProcessCommandLine contains " /ma " or ProcessCommandLine contains " –ma " or ProcessCommandLine contains " —ma " or ProcessCommandLine contains " ―ma " or ProcessCommandLine contains " -mm " or ProcessCommandLine contains " /mm " or ProcessCommandLine contains " –mm " or ProcessCommandLine contains " —mm " or ProcessCommandLine contains " ―mm " or ProcessCommandLine contains " -mp " or ProcessCommandLine contains " /mp " or ProcessCommandLine contains " –mp " or ProcessCommandLine contains " —mp " or ProcessCommandLine contains " ―mp ") and (ProcessCommandLine contains " ls" or ProcessCommandLine contains " keyiso" or ProcessCommandLine contains " samss")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1036", "T1003"]
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
}