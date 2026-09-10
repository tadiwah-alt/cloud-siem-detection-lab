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

