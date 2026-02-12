resource "aws_vpc" "agenthub" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "agenthub-${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_s3_bucket" "artifacts" {
  bucket = var.artifact_bucket_name

  tags = {
    Name        = "agenthub-${var.environment}-artifacts"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "artifacts_versioning" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_db_subnet_group" "agenthub" {
  name       = "agenthub-${var.environment}-db-subnets"
  subnet_ids = []
}

resource "aws_db_instance" "postgres" {
  identifier             = "agenthub-${var.environment}-postgres"
  engine                 = "postgres"
  engine_version         = "16.3"
  instance_class         = var.db_instance_class
  allocated_storage      = var.db_allocated_storage
  max_allocated_storage  = 200
  db_subnet_group_name   = aws_db_subnet_group.agenthub.name
  skip_final_snapshot    = false
  backup_retention_period = 7
  deletion_protection    = true
  storage_encrypted      = true
  publicly_accessible    = false

  tags = {
    Name        = "agenthub-${var.environment}-postgres"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_dashboard" "cost_and_reliability" {
  dashboard_name = "agenthub-${var.environment}-cost-and-reliability"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        x = 0
        y = 0
        width = 12
        height = 6
        properties = {
          metrics = [["AWS/Billing", "EstimatedCharges", "Currency", "USD"]]
          period  = 21600
          stat    = "Maximum"
          region  = var.aws_region
          title   = "Estimated Monthly Spend"
        }
      }
    ]
  })
}
