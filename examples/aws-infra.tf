variable "base_domain"      {
  description = "ex: example.com"
}
variable "office_ip"        {
  description = "ex: 123.123.123.123"
}
variable "db_user"          {
  description = "ex: dbuser"
}
variable "db_pass"          {
  description = "db password"
}

provider "aws" {
  #access_key		= "${var.access_key}"
  #secret_key		= "${var.secret_key}"
  region		= "us-east-1"
}

data "aws_ami" "ubuntu18lts" {
  most_recent		= true
  owners                = ["099720109477"]
  filter {
    name		= "name"
    values		= ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20190212.1"]
  }
}

resource "aws_vpc" "dev-vpc" {
  cidr_block		= "10.0.0.0/16"
  enable_dns_support	= true
  enable_dns_hostnames	= true
  tags {
    Name		= "dev-vpc"
  }
}

resource "aws_internet_gateway" "dev-gateway" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  tags {
    Name		= "dev-gateway"
  }
}

resource "aws_route_table" "dev-public-routing" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  tags {
    Name		= "dev-public-routing"
  }
  route {
    cidr_block		= "0.0.0.0/0"
    gateway_id		= "${aws_internet_gateway.dev-gateway.id}"
  }
}

resource "aws_route_table" "dev-private-routing" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  tags {
    Name		= "dev-private-routing"
  }
}

resource "aws_subnet" "dev-public-a" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  availability_zone	= "us-east-1a"
  cidr_block		= "10.0.1.0/24"
  tags {
    Name		= "dev-public-a"
  }
}

resource "aws_route_table_association" "dev-public-routing-dev-public-a" {
  route_table_id	= "${aws_route_table.dev-public-routing.id}"
  subnet_id		= "${aws_subnet.dev-public-a.id}"
}

resource "aws_subnet" "dev-public-b" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  availability_zone	= "us-east-1b"
  cidr_block		= "10.0.2.0/24"
  tags {
    Name		= "dev-public-b"
  }
}

resource "aws_route_table_association" "dev-public-routing-dev-public-b" {
  route_table_id	= "${aws_route_table.dev-public-routing.id}"
  subnet_id		= "${aws_subnet.dev-public-b.id}"
}

resource "aws_subnet" "dev-public-c" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  availability_zone	= "us-east-1c"
  cidr_block		= "10.0.3.0/24"
  tags {
    Name		= "dev-public-c"
  }
}

resource "aws_route_table_association" "dev-public-routing-dev-public-c" {
  route_table_id	= "${aws_route_table.dev-public-routing.id}"
  subnet_id		= "${aws_subnet.dev-public-c.id}"
}

resource "aws_subnet" "dev-private-a" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  availability_zone	= "us-east-1a"
  cidr_block		= "10.0.11.0/24"
  tags {
    Name		= "dev-private-a"
  }
}

resource "aws_route_table_association" "dev-private-routing-dev-private-a" {
  route_table_id	= "${aws_route_table.dev-private-routing.id}"
  subnet_id		= "${aws_subnet.dev-private-a.id}"
}

resource "aws_subnet" "dev-private-b" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  availability_zone	= "us-east-1b"
  cidr_block		= "10.0.12.0/24"
  tags {
    Name		= "dev-private-b"
  }
}

resource "aws_route_table_association" "dev-private-routing-dev-private-b" {
  route_table_id	= "${aws_route_table.dev-private-routing.id}"
  subnet_id		= "${aws_subnet.dev-private-b.id}"
}

resource "aws_subnet" "dev-private-c" {
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  availability_zone	= "us-east-1c"
  cidr_block		= "10.0.13.0/24"
  tags {
    Name		= "dev-private-c"
  }
}

resource "aws_route_table_association" "dev-private-routing-dev-private-c" {
  route_table_id	= "${aws_route_table.dev-private-routing.id}"
  subnet_id		= "${aws_subnet.dev-private-c.id}"
}

resource "aws_security_group" "dev-bastion-secgrp" {
  name			= "dev-bastion-secgrp"
  description		= "allows ssh"
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  tags {
    Name		= "dev-bastion-secgrp"
  }
  ingress {
    from_port		= "22"
    to_port		= "22"
    protocol		= "tcp"
    cidr_blocks		= ["${var.office_ip}/32"]
  }
  ingress {
    from_port		= "-1"
    to_port		= "-1"
    protocol		= "icmp"
    cidr_blocks		= ["10.0.0.0/16", "${var.office_ip}/32"]
  }
  egress {
    from_port		= "0"
    to_port		= "0"
    protocol		= "-1"
    cidr_blocks		= ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "dev-public-secgrp" {
  name			= "dev-public-secgrp"
  description		= "allows http,https"
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  tags {
    Name		= "dev-public-secgrp"
  }
  ingress {
    from_port		= "0"
    to_port		= "0"
    protocol		= "-1"
    self		= true
  }
  ingress {
    from_port		= "22"
    to_port		= "22"
    protocol		= "tcp"
    cidr_blocks		= ["${aws_instance.dev-bastion.private_ip}/32"]
  }
  ingress {
    from_port		= "80"
    to_port		= "80"
    protocol		= "tcp"
    cidr_blocks		= ["0.0.0.0/0"]
  }
  ingress {
    from_port		= "443"
    to_port		= "443"
    protocol		= "tcp"
    cidr_blocks		= ["0.0.0.0/0"]
  }
  ingress {
    from_port		= "-1"
    to_port		= "-1"
    protocol		= "icmp"
    cidr_blocks		= ["10.0.0.0/16"]
  }
  egress {
    from_port		= "0"
    to_port		= "0"
    protocol		= "-1"
    cidr_blocks		= ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "dev-private-secgrp" {
  name			= "dev-private-secgrp"
  description		= "deny inbound, allow outbound"
  vpc_id		= "${aws_vpc.dev-vpc.id}"
  tags {
    Name		= "dev-private-secgrp"
  }
  ingress {
    from_port		= "0"
    to_port		= "0"
    protocol		= "-1"
    self		= true
  }
  ingress {
    from_port		= "22"
    to_port		= "22"
    protocol		= "tcp"
    cidr_blocks		= ["${aws_instance.dev-bastion.private_ip}/32"]
  }
  ingress {
    from_port		= "5432"
    to_port		= "5432"
    protocol		= "tcp"
    security_groups	= ["${aws_security_group.dev-public-secgrp.id}"]
  }
  ingress {
    from_port		= "-1"
    to_port		= "-1"
    protocol		= "icmp"
    cidr_blocks		= ["10.0.0.0/16"]
  }
  egress {
    from_port		= "0"
    to_port		= "0"
    protocol		= "-1"
    cidr_blocks		= ["0.0.0.0/0"]
  }
}

resource "aws_instance" "dev-bastion" {
  instance_type		= "t3.nano"
  ami			= "${data.aws_ami.ubuntu18lts.image_id}"
  subnet_id		= "${aws_subnet.dev-public-a.id}"
  vpc_security_group_ids	= ["${aws_security_group.dev-bastion-secgrp.id}"]
  key_name		= "dev-bastion"
  credit_specification {
    cpu_credits		= "unlimited"
  }
  tags {
    Name		= "dev-bastion"
  }
}

resource "aws_eip" "dev-bastion-ip" {
  vpc			= true
  instance		= "${aws_instance.dev-bastion.id}"
  tags {
    Name		= "dev-bastion-ip"
  }
}

resource "aws_instance" "dev-www-ec2" {
  instance_type		= "t3.micro"
  ami			= "${data.aws_ami.ubuntu18lts.image_id}"
  subnet_id		= "${aws_subnet.dev-public-a.id}"
  vpc_security_group_ids	= ["${aws_security_group.dev-public-secgrp.id}"]
  key_name		= "dev-ubuntu"
  credit_specification {
    cpu_credits		= "unlimited"
  }
  tags {
    Name		= "dev-www-ec2"
  }
}

resource "aws_eip" "dev-www-ip" {
  vpc			= true
  instance		= "${aws_instance.dev-www-ec2.id}"
  tags {
    Name		= "dev-www-ip"
  }
}

resource "aws_db_subnet_group" "rds-subnetgrp" {
  name			= "rds-subnetgrp"
  subnet_ids		= ["${aws_subnet.dev-private-a.id}", "${aws_subnet.dev-private-c.id}"]
  tags {
    Name		= "rds-subnetgrp"
  }
}

resource "aws_db_parameter_group" "pg10-paramgrp" {
  name			= "pg10-paramgrp"
  family		= "postgres10"
  parameter {
    name	= "work_mem"
    value	= "16384"
  }
  parameter {
    name	= "maintenance_work_mem"
    value	= "32768"
  }
  parameter {
    name	= "shared_preload_libraries"
    value	= "auto_explain,pg_stat_statements"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "db-master" {
  allocated_storage	= "20"
  auto_minor_version_upgrade	= "true"
  availability_zone	= "us-east-1a"
  backup_retention_period	= "14"
  backup_window		= "00:00-00:30"
  copy_tags_to_snapshot	= "true"
  db_subnet_group_name	= "rds-subnetgrp"
  engine		= "postgres"
  engine_version	= "10.6"
  identifier		= "db-master"
  instance_class	= "db.t2.small"
  monitoring_interval	= "60"
  monitoring_role_arn	= "${aws_iam_role.rds-monitoring-role.arn}"
  multi_az		= "false"
  parameter_group_name	= "pg10-paramgrp"
  password		= "${var.db_pass}"
  port			= "5432"
  publicly_accessible	= "false"
  storage_encrypted	= "false"
  storage_type		= "gp2"
  #timezone		= "UTC"
  username		= "${var.db_user}"
  vpc_security_group_ids	= ["${aws_security_group.dev-private-secgrp.id}"]
  #tags			= {
  #  Name		= "db-master"
  #}
}

resource "aws_db_instance" "db-slave" {
  allocated_storage	= "20"
  availability_zone	= "us-east-1c"
  copy_tags_to_snapshot	= "true"
  identifier		= "db-slave"
  instance_class	= "db.t2.micro"
  monitoring_interval	= "60"
  monitoring_role_arn	= "${aws_iam_role.rds-monitoring-role.arn}"
  multi_az		= "false"
  parameter_group_name	= "pg10-paramgrp"
  port			= "5432"
  publicly_accessible	= "false"
  replicate_source_db	= "${aws_db_instance.db-master.id}"
  storage_encrypted	= "false"
  storage_type		= "gp2"
  #timezone		= "UTC"
  vpc_security_group_ids	= ["${aws_security_group.dev-private-secgrp.id}"]
  #tags			= {
  #  Name		= "db-slave"
  #}
}

resource "aws_route53_zone" "public-dev" {
  name			= "${var.base_domain}"
  tags {
    Name		= "public-dev"
  }
}

resource "aws_route53_record" "public-dev-dev-bastion-A" {
  zone_id		= "${aws_route53_zone.public-dev.zone_id}"
  type			= "A"
  name			= "dev-bastion"
  ttl			= "5"
  records		= ["${aws_eip.dev-bastion-ip.public_ip}"]
}

resource "aws_route53_record" "public-dev-dev-www-A" {
  zone_id		= "${aws_route53_zone.public-dev.zone_id}"
  type			= "A"
  name			= "dev-www"
  ttl			= "5"
  records		= ["${aws_eip.dev-www-ip.public_ip}"]
}

resource "aws_route53_zone" "private-dev" {
  name			= "dev"
  vpc {
    vpc_id		= "${aws_vpc.dev-vpc.id}"
  }
  tags {
    Name		= "private-dev"
  }
}

resource "aws_route53_record" "private-dev-bastion-A" {
  zone_id		= "${aws_route53_zone.private-dev.zone_id}"
  type			= "A"
  name			= "bastion"
  ttl			= "5"
  records		= ["${aws_instance.dev-bastion.private_ip}"]
}

resource "aws_route53_record" "private-dev-www-A" {
  zone_id		= "${aws_route53_zone.private-dev.zone_id}"
  type			= "A"
  name			= "www"
  ttl			= "5"
  records		= ["${aws_instance.dev-www-ec2.private_ip}"]
}

resource "aws_iam_role" "rds-monitoring-role" {
  name                  = "rds-monitoring-role"
  path                  = "/"
  assume_role_policy    = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "monitoring.rds.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_policy_attachment" "AmazonRDSEnhancedMonitoringRole-policy-attachment" {

  name                  = "AmazonRDSEnhancedMonitoringRole-policy-attachment"
  policy_arn            = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  groups                = []
  users                 = []
  roles                 = ["rds-monitoring-role"]
}

output "bastion_ip" {
  value = "${aws_eip.dev-bastion-ip.public_ip}"
}

output "www_ip" {
  value = "${aws_eip.dev-www-ip.public_ip}"
}

output "rds_master_endpoint" {
  value = "${aws_db_instance.db-master.endpoint}"
}

output "rds_slave_endpoint" {
  value = "${aws_db_instance.db-slave.endpoint}"
}

