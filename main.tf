terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.63.0"
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


