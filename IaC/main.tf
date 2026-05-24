provider "aws" {
  region = "eu-central-1"
}

#--------------------------------------------------
# Networking
#--------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "172.31.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "detection-lab"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "detection-lab-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "172.31.2.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "detection-lab-public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "detection-lab-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

#--------------------------------------------------
# Security Group
#--------------------------------------------------

variable "operator_ip" {
  description = "Your public IP address in CIDR notation (e.g., x.x.x.x/32)"
  type        = string
}

resource "aws_security_group" "ec2" {
  name        = "detection-lab-sg"
  description = "Detection Lab EC2"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from operator only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "detection-lab-sg"
  }
}

#--------------------------------------------------
# AMI
#--------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  owners = ["099720109477"]
}

#--------------------------------------------------
# Caller Identity
#--------------------------------------------------

data "aws_caller_identity" "current" {}

#--------------------------------------------------
# S3 Buckets
#--------------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "flow_logs" {
  bucket = "vpc-flow-logs-${data.aws_caller_identity.current.account_id}"
}

#--------------------------------------------------
# CloudTrail Bucket Policy
#--------------------------------------------------

data "aws_iam_policy_document" "cloudtrail_s3" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = [
      "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_s3.json
}

#--------------------------------------------------
# CloudTrail
#--------------------------------------------------

resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail
  ]
}

#--------------------------------------------------
# VPC Flow Logs
#--------------------------------------------------

data "aws_iam_policy_document" "flow_logs_bucket" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = ["${aws_s3_bucket.flow_logs.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.flow_logs.arn]
  }
}

resource "aws_s3_bucket_policy" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_bucket.json
}

resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.flow_logs.arn

  depends_on = [
    aws_s3_bucket_policy.flow_logs
  ]
}

#--------------------------------------------------
# SSM Parameters
#--------------------------------------------------

resource "aws_ssm_parameter" "cloudtrail_bucket" {
  name  = "/logging/cloudtrail/bucket"
  value = aws_s3_bucket.cloudtrail.bucket
  type  = "String"
}

resource "aws_ssm_parameter" "flow_logs_bucket" {
  name  = "/logging/flow_logs/bucket"
  value = aws_s3_bucket.flow_logs.bucket
  type  = "String"
}

#--------------------------------------------------
# EC2 Instance
#--------------------------------------------------

resource "aws_instance" "test_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.ec2.id]

  tags = {
    Name = "test-server"
  }
}

#--------------------------------------------------
# IAM User (Read-only pipeline)
#--------------------------------------------------

resource "aws_iam_user" "pipeline" {
  name = "detection-lab-pipeline"

  tags = {
    Name = "detection-lab-pipeline"
  }
}

resource "aws_iam_access_key" "pipeline" {
  user = aws_iam_user.pipeline.name
}

data "aws_iam_policy_document" "pipeline_read_only" {
  statement {
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.cloudtrail.arn,
      "${aws_s3_bucket.cloudtrail.arn}/*",
      aws_s3_bucket.flow_logs.arn,
      "${aws_s3_bucket.flow_logs.arn}/*"
    ]
  }
}

resource "aws_iam_user_policy" "pipeline_read_only" {
  name   = "detection-lab-pipeline-read-only"
  user   = aws_iam_user.pipeline.name
  policy = data.aws_iam_policy_document.pipeline_read_only.json
}

#--------------------------------------------------
# Store pipeline credentials in SSM
#--------------------------------------------------

resource "aws_ssm_parameter" "pipeline_key_id" {
  name  = "/pipeline/credentials/access_key_id"
  value = aws_iam_access_key.pipeline.id
  type  = "String"
}

resource "aws_ssm_parameter" "pipeline_secret" {
  name  = "/detection-lab/pipeline/secret_access_key"
  value = aws_iam_access_key.pipeline.secret
  type  = "SecureString"
}