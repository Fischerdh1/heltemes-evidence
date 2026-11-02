variable "region" {
  description = "AWS region for the research stack. Initial deployment targets commercial AWS."
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  type    = string
  default = "heltemes-evidence"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,23}$", var.project_name))
    error_message = "Use 3-24 lowercase letters, digits or hyphens, beginning with a letter."
  }
}

variable "sec_user_agent" {
  description = "Application name and a real monitored email address; stored in Lambda configuration and private Terraform state."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.sec_user_agent) <= 240 && can(regex("^[^\r\n]+ [^@\r\n ]+@[^@\r\n ]+\\.[^@\r\n ]+$", var.sec_user_agent)) && !can(regex("(?i)(example\\.(com|org|net)|your[-_]?email|you@)", var.sec_user_agent))
    error_message = "Provide an application name and your real monitored contact email, not example.com."
  }
}

variable "sec_cik" {
  type    = string
  default = "0000320193"
  validation {
    condition     = can(regex("^[0-9]{1,10}$", var.sec_cik)) && can(regex("[1-9]", var.sec_cik))
    error_message = "CIK must be 1-10 digits and nonzero."
  }
}

variable "sec_forms" {
  type    = list(string)
  default = ["10-Q", "10-Q/A"]
  validation {
    condition     = length(var.sec_forms) >= 1 && length(var.sec_forms) <= 10 && alltrue([for form in var.sec_forms : contains(["10-Q", "10-Q/A", "10-K", "10-K/A", "8-K", "8-K/A", "20-F", "20-F/A", "6-K", "6-K/A"], form)])
    error_message = "Select 1-10 supported forms (10-Q, 10-K, 8-K, 20-F, 6-K and /A amendments)."
  }
}

variable "filing_limit" {
  type    = number
  default = 2
  validation {
    condition     = contains([1, 2, 3], var.filing_limit)
    error_message = "Each run may select only 1, 2 or 3 filings."
  }
}

variable "lambda_zip_path" {
  description = "Path relative to infra/ (or absolute), produced by scripts/package_lambda.py."
  type        = string
  default     = "../dist/collector.zip"
}

variable "enable_schedule" {
  description = "Keep false until a manual invocation, access checks and alarms are verified."
  type        = bool
  default     = false
}

variable "schedule_expression" {
  description = "UTC schedule; default is once daily."
  type        = string
  default     = "cron(0 13 * * ? *)"
}

variable "enable_audit_trail" {
  description = "Management events plus object data events scoped to the evidence bucket; additional AWS charges apply."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Optional address for error/throttle alarms and budget warnings. Confirm the SNS subscription email."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = var.alert_email == "" || can(regex("^[^@ ]+@[^@ ]+\\.[^@ ]+$", var.alert_email))
    error_message = "Use an email address or an empty string."
  }
}

variable "monthly_budget_usd" {
  description = "Optional account-wide actual spend warning (0 disables). This is not a hard cost cap. Requires alert_email."
  type        = number
  default     = 0
  validation {
    condition     = var.monthly_budget_usd >= 0
    error_message = "Budget must be zero (disabled) or a positive dollar amount."
  }
}

variable "github_oidc_provider_arn" {
  description = "Optional existing GitHub OIDC provider ARN. This stack does not create an identity provider."
  type        = string
  default     = ""
}

variable "github_oidc_subject" {
  description = "Exact subject for this repository's protected production environment, including immutable IDs if applicable. No wildcards."
  type        = string
  default     = ""
  validation {
    condition     = var.github_oidc_subject == "" || (can(regex("^repo:[^/*?]+/[^/*?:]+:environment:production$", var.github_oidc_subject)) && !can(regex("[\\r\\n]", var.github_oidc_subject)))
    error_message = "Supply one exact repository subject ending :environment:production, with no wildcard."
  }
}
