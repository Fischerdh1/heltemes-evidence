resource "aws_s3_bucket" "evidence" {
  bucket        = local.bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "CollectorMustCreateConditionally"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/evidence/*"
        Condition = {
          ArnEquals       = { "aws:PrincipalArn" = aws_iam_role.collector.arn }
          StringNotEquals = { "s3:if-none-match" = "*" }
        }
      }
    ]
  })
}

resource "aws_iam_role" "collector" {
  name = "${var.project_name}-collector"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "collector" {
  name              = "/aws/lambda/${var.project_name}-collector"
  retention_in_days = 30
}

resource "aws_iam_role_policy" "collector" {
  role = aws_iam_role.collector.id
  name = "write-new-evidence-and-logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = ["s3:PutObject"]
        Resource  = "${aws_s3_bucket.evidence.arn}/evidence/*"
        Condition = { StringEquals = { "s3:if-none-match" = "*" } }
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.collector.arn}:*"
      }
    ]
  })
}

# Attach this policy to a separately managed human/SSO role. No credentials or
# broadly trusted reader role are created by the project.
resource "aws_iam_policy" "reader" {
  name = "${var.project_name}-evidence-reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = ["s3:ListBucket", "s3:ListBucketVersions"]
        Resource  = aws_s3_bucket.evidence.arn
        Condition = { StringLike = { "s3:prefix" = ["evidence", "evidence/*"] } }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.evidence.arn}/evidence/*"
      }
    ]
  })
}

resource "aws_lambda_function" "collector" {
  function_name                  = "${var.project_name}-collector"
  role                           = aws_iam_role.collector.arn
  runtime                        = "python3.12"
  handler                        = "cloud.handler.handler"
  filename                       = var.lambda_zip_path
  source_code_hash               = filebase64sha256(var.lambda_zip_path)
  memory_size                    = 256
  timeout                        = 180
  reserved_concurrent_executions = 1
  architectures                  = ["arm64"]

  environment {
    variables = {
      EVIDENCE_BUCKET  = aws_s3_bucket.evidence.id
      SEC_USER_AGENT   = var.sec_user_agent
      SEC_CIK          = var.sec_cik
      SEC_FORMS        = join(",", var.sec_forms)
      SEC_FILING_LIMIT = tostring(var.filing_limit)
    }
  }
  depends_on = [aws_iam_role_policy.collector, aws_s3_bucket_policy.evidence, aws_s3_bucket_versioning.evidence]
}

# No automatic retries after application failure: each failed/partial run is
# preserved and must be investigated. This bounds duplicated collection.
resource "aws_lambda_function_event_invoke_config" "collector" {
  function_name                = aws_lambda_function.collector.function_name
  maximum_event_age_in_seconds = 300
  maximum_retry_attempts       = 0
}
