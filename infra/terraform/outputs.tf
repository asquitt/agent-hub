output "vpc_id" {
  value       = aws_vpc.agenthub.id
  description = "VPC ID"
}

output "artifact_bucket" {
  value       = aws_s3_bucket.artifacts.bucket
  description = "Artifact bucket name"
}

output "db_instance_endpoint" {
  value       = aws_db_instance.postgres.endpoint
  description = "Postgres endpoint"
}
