"""Tests for AWS patterns: Account IDs, ARNs, S3 buckets."""


class TestAccountID:
    def test_in_arn_context(self, p):
        # Account ID within an ARN is handled by the ARN pattern
        text = 'account = "123456789012"'
        result, mapping = p.anonymize(text)
        assert "123456789012" not in result

    def test_after_colon(self, p):
        text = "account:123456789012:role"
        result, _ = p.anonymize(text)
        assert "123456789012" not in result


class TestARN:
    def test_iam_role(self, p):
        arn = "arn:aws:iam::123456789012:role/deploy-prod"
        result, mapping = p.anonymize(arn)
        assert "123456789012" not in result
        assert "deploy-prod" not in result
        assert "arn:aws:iam:" in result
        assert "role/" in result

    def test_s3_arn(self, p):
        arn = "arn:aws:s3::123456789012:my-bucket/*"
        result, mapping = p.anonymize(arn)
        assert "123456789012" not in result

    def test_lambda_arn(self, p):
        arn = "arn:aws:lambda:us-east-1:123456789012:function/my-func"
        result, mapping = p.anonymize(arn)
        assert "123456789012" not in result
        assert "my-func" not in result
        assert "us-east-1" in result  # region preserved


class TestS3Bucket:
    def test_s3_uri(self, p):
        text = "bucket = s3://my-production-logs/data/"
        result, mapping = p.anonymize(text)
        assert "my-production-logs" not in result
        assert "redacted-bucket" in result

    def test_s3_triple_colon(self, p):
        text = "arn:aws:s3:::my-production-logs"
        result, _ = p.anonymize(text)
        assert "my-production-logs" not in result
