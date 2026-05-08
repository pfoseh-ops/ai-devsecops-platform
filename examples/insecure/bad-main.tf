resource "aws_s3_bucket" "bad_bucket" {
  bucket = "bad-public-style-bucket-example"
}

resource "aws_security_group" "bad_sg" {
  name = "bad-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "bad_db" {
  allocated_storage = 10
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  username          = "admin"
  password          = "SuperSecret123"
}

resource "aws_iam_policy" "wild" {
  name   = "wild-policy"
  policy = <<POL
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POL
}
