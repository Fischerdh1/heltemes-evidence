resource "aws_scheduler_schedule_group" "collector" {
  name = "${var.project_name}-collection"
}

resource "aws_iam_role" "scheduler" {
  name = "${var.project_name}-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_scheduler_schedule_group.collector.arn }
      }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-only-collector"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.collector.arn
    }]
  })
}

resource "aws_scheduler_schedule" "collector" {
  name                         = "${var.project_name}-daily"
  group_name                   = aws_scheduler_schedule_group.collector.name
  state                        = var.enable_schedule ? "ENABLED" : "DISABLED"
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = "UTC"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_lambda_function.collector.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = "{}"
    retry_policy {
      maximum_event_age_in_seconds = 300
      maximum_retry_attempts       = 0
    }
  }
  depends_on = [aws_iam_role_policy.scheduler]
}

resource "aws_sns_topic" "alerts" {
  count = nonsensitive(var.alert_email != "") ? 1 : 0
  name  = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = nonsensitive(var.alert_email != "") ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "alerts" {
  count = nonsensitive(var.alert_email != "") ? 1 : 0
  arn   = aws_sns_topic.alerts[0].arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowProjectCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts[0].arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudwatch:${var.region}:${data.aws_caller_identity.current.account_id}:alarm:${var.project_name}-*" }
      }
    }]
  })
}

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.project_name}-collection-errors"
  alarm_description   = "A failed or partial collection raises Lambda Errors. Inspect logs and run manifests."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.collector.function_name }
  alarm_actions       = aws_sns_topic.alerts[*].arn
}

resource "aws_cloudwatch_metric_alarm" "throttles" {
  alarm_name          = "${var.project_name}-collection-throttles"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.collector.function_name }
  alarm_actions       = aws_sns_topic.alerts[*].arn
}

resource "aws_cloudwatch_metric_alarm" "missing_invocation" {
  count               = var.enable_schedule ? 1 : 0
  alarm_name          = "${var.project_name}-missing-daily-invocation"
  alarm_description   = "No invocation observed during a full daily period. Applies to the supplied daily schedule. Review this alarm if changing cadence."
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  dimensions          = { FunctionName = aws_lambda_function.collector.function_name }
  alarm_actions       = aws_sns_topic.alerts[*].arn
}

resource "aws_budgets_budget" "monthly" {
  count        = var.monthly_budget_usd > 0 ? 1 : 0
  name         = "${var.project_name}-account-cost-warning"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
  lifecycle {
    precondition {
      condition     = var.alert_email != ""
      error_message = "Set alert_email when enabling the optional account-wide budget warning."
    }
  }
}

# Optional role can update ONLY this Lambda's code, not Terraform infrastructure.
# OIDC provider must already exist; no long-lived AWS keys are placed in GitHub.
resource "aws_iam_role" "github_code_deployer" {
  count = var.github_oidc_provider_arn != "" ? 1 : 0
  name  = "${var.project_name}-github-code-deployer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.github_oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = var.github_oidc_subject
        }
      }
    }]
  })
  lifecycle {
    precondition {
      condition     = var.github_oidc_subject != ""
      error_message = "An exact protected-environment GitHub subject is required with an OIDC provider."
    }
  }
}

resource "aws_iam_role_policy" "github_code_deployer" {
  count = var.github_oidc_provider_arn != "" ? 1 : 0
  name  = "update-only-collector-code"
  role  = aws_iam_role.github_code_deployer[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:UpdateFunctionCode", "lambda:GetFunctionConfiguration"]
      Resource = aws_lambda_function.collector.arn
    }]
  })
}
