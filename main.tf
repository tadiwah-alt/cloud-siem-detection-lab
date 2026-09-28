terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.63.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }

  }
}


provider "aws" {
  region = "us-east-2"

}


resource "aws_s3_bucket" "cloud_siem_lab_cloudtrail_bucket" {
  bucket = "cloud-siem-lab-cloudtrail-josh"


}


resource "aws_s3_bucket_versioning" "cloud_siem_lab_cloudtrail_bucket_versioning" {
  bucket = aws_s3_bucket.cloud_siem_lab_cloudtrail_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}


resource "aws_s3_bucket_public_access_block" "cloud_siem_lab_cloudtrail_bucket_public_access_block" {
  bucket = aws_s3_bucket.cloud_siem_lab_cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}



resource "aws_s3_bucket_lifecycle_configuration" "cloud_siem_lab_cloudtrail_bucket_lifecycle" {
  bucket = aws_s3_bucket.cloud_siem_lab_cloudtrail_bucket.id

  rule {
    id = "Allow deletion of trails"

    expiration {
      days = 30
    }

    status = "Enabled"
  }
}





resource "aws_cloudtrail" "cloud_siem_lab_trail" {
  depends_on = [aws_s3_bucket_policy.cloudtrail_s3_policy]

  name                          = "cloud-siem-lab-trail"
  s3_bucket_name                = aws_s3_bucket.cloud_siem_lab_cloudtrail_bucket.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
}



data "aws_iam_policy_document" "cloudtrail_s3_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloud_siem_lab_cloudtrail_bucket.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/cloud-siem-lab-trail"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloud_siem_lab_cloudtrail_bucket.arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/cloud-siem-lab-trail"]
    }
  }
}


resource "aws_s3_bucket_policy" "cloudtrail_s3_policy" {
  bucket = aws_s3_bucket.cloud_siem_lab_cloudtrail_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_s3_policy.json
}


data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}


resource "aws_guardduty_detector" "cloud_siem_lab_guardduty_detector" {
  enable = true
}

resource "aws_cloudwatch_event_rule" "cloud_siem_lab_EventBridge" {
  name        = "disable-iamuser-credentials"
  description = "Disable Compromised IAM User Credentials"

  event_pattern = jsonencode({
    source = [
      "aws.guardduty"
    ]

    detail = {

      type = [
        "CredentialAccess:IAMUser/CompromisedCredentials"
      ]

    }

  })

}


data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}


resource "aws_iam_role" "lambda_iam_role" {
  name               = "cloud-siem-lab-lambda-iam-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}


data "aws_iam_policy_document" "lambda_iam_policy" {

  statement {
    sid    = "AWSLambdaPermission"
    effect = "Allow"


    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }


  statement {
    sid       = "AllowCreateLogGroup"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup"]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:*"]
  }

  statement {
    sid       = "AllowWriteLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.lambda_iam_handler.function_name}:*"]
  }

}


resource "aws_iam_role_policy" "lambda_iam_policy_role" {
  role   = aws_iam_role.lambda_iam_role.name
  policy = data.aws_iam_policy_document.lambda_iam_policy.json
}


data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda/disable_compromised_key.py"
  output_path = "${path.module}/lambda/disable_compromised_key.zip"
}

resource "aws_lambda_function" "lambda_iam_handler" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "disable-compromised-key-lambda-function"
  role             = aws_iam_role.lambda_iam_role.arn
  handler          = "disable_compromised_key.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 10

  runtime = "python3.12"

}

resource "aws_cloudwatch_event_target" "cloud_siem_lab_EventBridge_Target" {
  target_id = "cloud-siem-lab-eventBridge-lambda-iam-role-target"
  rule      = aws_cloudwatch_event_rule.cloud_siem_lab_EventBridge.name
  arn       = aws_lambda_function.lambda_iam_handler.arn

}


resource "aws_lambda_permission" "cloud_siem_lab_EventBridge_lambda_permissions" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_iam_handler.arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloud_siem_lab_EventBridge.arn

}