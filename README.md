# Terraformdsl.rb README

Overview
--------

Terraformdsl.rb is a DSL library to generate *.tf files of Terraform.

See 'examples/' directory for examples.


Installation
------------

Add this line to your application's Gemfile:

```ruby
gem 'terraformdsl'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install terraformdsl


Examples
--------

See 'examples/' directory for practical examples.

myproj-infra.rb:

```ruby
require 'terraformdsl/aws'

region    = ENV['AWS_DEFAULT_REGION']
prefix    = "myproj"
vpc       = nil
public_dns_records  = []
private_dns_records = []

output    = TerraformDSL::Outputs.new
var       = TerraformDSL::Variables.new
var.define :base_domain  , "ex: example.com"
var.define :office_ip    , "ex: 123.123.123.123"

aws_infra = TerraformDSL::AWS.infra()
aws_infra.region(region) {

  ## Availability Zone
  az_a = AZ("#{region}a")   # ex: 'ap-east-1a'
  az_b = AZ("#{region}b")   # ex: 'ap-east-1b'
  az_c = AZ("#{region}c")   # ex: 'ap-east-1c'
  az_d = AZ("#{region}d")   # ex: 'ap-east-1d'

  ## AMI
  ubuntu_ami = AMI('ubuntu18lts', "099720109477",
    "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20190212.1"
  )

  ## VPC
  vpc = VPC("#{prefix}-vpc", "10.0.0.0/16") {|vpc|
    sshkey_name = "#{prefix}-ubuntu"

    ### Internet Gateway
    gateway    = InternetGateway("#{prefix}-gateway")

    ## Route Table
    public_rt  = RouteTable("#{prefix}-public-routing") {
      Route(nil, gateway: gateway)
    }
    private_rt = RouteTable("#{prefix}-private-routing") {
      #Route(nil, gateway: gateway)
    }

    ### Subnet
    public_a  = Subnet("#{prefix}-public-a" , "10.0.1.0/24" , az_a, public_rt)
    public_b  = Subnet("#{prefix}-public-b" , "10.0.2.0/24" , az_b, public_rt)
    private_a = Subnet("#{prefix}-private-a", "10.0.11.0/24", az_a, private_rt)
    private_b = Subnet("#{prefix}-private-b", "10.0.12.0/24", az_b, private_rt)

    ## Security Group
    public_secgrp  = SecurityGroup("#{prefix}-public-secgrp", "allows http,https") {
      Ingress(:any ,    0, :self)
      Ingress(:tcp ,   22, "#{var.office_ip}/32")
      Ingress(:tcp ,   80, nil)
      Ingress(:tcp ,  443, nil)
      Ingress(:icmp,  nil, vpc.cidr)
      Egress( :any ,    0, nil)
    }

    ### EC2 and EIP
    let public_a, public_secgrp, ubuntu_ami, sshkey_name do
      |sn, sg, ami, kn|
      www_ec2  = EC2("#{prefix}-www-ec2" , "t3.micro", ami, sn, sg, kn)
      www_ip   = EIP("#{prefix}-www-ip"  , www_ec2)
      public_dns_records  << [:A, "www"  , www_ip]
      private_dns_records << [:A, "www"  , www_ec2]
      output[:www_ip] = www_ip.attr(:public_ip)
    end

  }#vpc

}#region


aws_infra.global {

  ## DNS
  Route53() {

    Zone("public-dns", var.base_domain) {
      public_dns_records.each do |type, name, value|
        Record(type, name, value)
      end
    }

    PrivateZone("private-dns", "internal", vpc) {
      private_dns_records.each do |type, name, value|
        Record(type, name, value)
      end
    }

  }

}


if __FILE__ == $0
  puts var.generate_tf()
  puts aws_infra.generate_tf()
  puts output.generate_tf()
end
```

Generate *.tf file:

```terminal
$ ruby myproj-infra.rb > myproj-infra.tf
```

myproj-infra.tf (genareated)

```terraform
variable "base_domain"      {
  description = "ex: example.com"
}
variable "office_ip"        {
  description = "ex: 123.123.123.123"
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

resource "aws_vpc" "myproj-vpc" {
  cidr_block		= "10.0.0.0/16"
  enable_dns_support	= true
  enable_dns_hostnames	= true
  tags {
    Name		= "myproj-vpc"
  }
}

resource "aws_internet_gateway" "myproj-gateway" {
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  tags {
    Name		= "myproj-gateway"
  }
}

resource "aws_route_table" "myproj-public-routing" {
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  tags {
    Name		= "myproj-public-routing"
  }
  route {
    cidr_block		= "0.0.0.0/0"
    gateway_id		= "${aws_internet_gateway.myproj-gateway.id}"
  }
}

resource "aws_route_table" "myproj-private-routing" {
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  tags {
    Name		= "myproj-private-routing"
  }
}

resource "aws_subnet" "myproj-public-a" {
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  availability_zone	= "us-east-1a"
  cidr_block		= "10.0.1.0/24"
  tags {
    Name		= "myproj-public-a"
  }
}

resource "aws_route_table_association" "myproj-public-routing-myproj-public-a" {
  route_table_id	= "${aws_route_table.myproj-public-routing.id}"
  subnet_id		= "${aws_subnet.myproj-public-a.id}"
}

resource "aws_subnet" "myproj-public-b" {
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  availability_zone	= "us-east-1b"
  cidr_block		= "10.0.2.0/24"
  tags {
    Name		= "myproj-public-b"
  }
}

resource "aws_route_table_association" "myproj-public-routing-myproj-public-b" {
  route_table_id	= "${aws_route_table.myproj-public-routing.id}"
  subnet_id		= "${aws_subnet.myproj-public-b.id}"
}

resource "aws_subnet" "myproj-private-a" {
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  availability_zone	= "us-east-1a"
  cidr_block		= "10.0.11.0/24"
  tags {
    Name		= "myproj-private-a"
  }
}

resource "aws_route_table_association" "myproj-private-routing-myproj-private-a" {
  route_table_id	= "${aws_route_table.myproj-private-routing.id}"
  subnet_id		= "${aws_subnet.myproj-private-a.id}"
}

resource "aws_subnet" "myproj-private-b" {
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  availability_zone	= "us-east-1b"
  cidr_block		= "10.0.12.0/24"
  tags {
    Name		= "myproj-private-b"
  }
}

resource "aws_route_table_association" "myproj-private-routing-myproj-private-b" {
  route_table_id	= "${aws_route_table.myproj-private-routing.id}"
  subnet_id		= "${aws_subnet.myproj-private-b.id}"
}

resource "aws_security_group" "myproj-public-secgrp" {
  name			= "myproj-public-secgrp"
  description		= "allows http,https"
  vpc_id		= "${aws_vpc.myproj-vpc.id}"
  tags {
    Name		= "myproj-public-secgrp"
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
    cidr_blocks		= ["${var.office_ip}/32"]
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

resource "aws_instance" "myproj-www-ec2" {
  instance_type		= "t3.micro"
  ami			= "${data.aws_ami.ubuntu18lts.image_id}"
  subnet_id		= "${aws_subnet.myproj-public-a.id}"
  vpc_security_group_ids	= ["${aws_security_group.myproj-public-secgrp.id}"]
  key_name		= "myproj-ubuntu"
  credit_specification {
    cpu_credits		= "unlimited"
  }
  tags {
    Name		= "myproj-www-ec2"
  }
}

resource "aws_eip" "myproj-www-ip" {
  vpc			= true
  instance		= "${aws_instance.myproj-www-ec2.id}"
  tags {
    Name		= "myproj-www-ip"
  }
}

resource "aws_route53_zone" "public-dns" {
  name			= "${var.base_domain}"
  tags {
    Name		= "public-dns"
  }
}

resource "aws_route53_record" "public-dns-www-A" {
  zone_id		= "${aws_route53_zone.public-dns.zone_id}"
  type			= "A"
  name			= "www"
  ttl			= "5"
  records		= ["${aws_eip.myproj-www-ip.public_ip}"]
}

resource "aws_route53_zone" "private-dns" {
  name			= "internal"
  vpc {
    vpc_id		= "${aws_vpc.myproj-vpc.id}"
  }
  tags {
    Name		= "private-dns"
  }
}

resource "aws_route53_record" "private-dns-www-A" {
  zone_id		= "${aws_route53_zone.private-dns.zone_id}"
  type			= "A"
  name			= "www"
  ttl			= "5"
  records		= ["${aws_instance.myproj-www-ec2.private_ip}"]
}

output "www_ip" {
  value = "${aws_eip.myproj-www-ip.public_ip}"
}

```


License
-------

MIT License
