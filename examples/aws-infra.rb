# -*- coding: utf-8 -*-

begin
  require 'terraformdsl/aws'
rescue LoadError
  require_relative '../lib/terraformdsl/aws'
end

region    = ENV['AWS_DEFAULT_REGION']  or abort("$AWS_DEFAULT_REGION required.")
app_env   = ENV['APP_ENV']             or abort("ERROR: $APP_ENV required.")
app_env =~ /^(prod|stg|dev)$/          or abort("ERROR: invalid $APP_ENV.")

var = TerraformDSL::Variables.new
var.define :base_domain  , "ex: example.com"
var.define :office_ip    , "ex: 123.123.123.123"
var.define :db_user      , "ex: dbuser"
var.define :db_pass      , "db password"

output = TerraformDSL::Outputs.new


vpc = nil
public_dns_records  = []
private_dns_records = []

aws_infra = TerraformDSL::AWS.infra()


aws_infra.region(region) {

  az_a = AZ("#{region}a")   # ex: 'ap-east-1a'
  az_b = AZ("#{region}b")   # ex: 'ap-east-1b'
  az_c = AZ("#{region}c")   # ex: 'ap-east-1c'
  az_d = AZ("#{region}d")   # ex: 'ap-east-1d'

  t3_nano  = "t3.nano"
  t3_micro = "t3.micro"

  prefix = app_env.downcase()

  ubuntu_ami = AMI('ubuntu18lts', "099720109477",
    "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20190212.1"
  )

  vpc = VPC("#{prefix}-vpc", "10.0.0.0/16") {|vpc|
    vpc_cidr = vpc.cidr
    ec2_sshkey_name     = "#{prefix}-ubuntu"
    bastion_sshkey_name = "#{prefix}-bastion"

    ### Internet Gateway
    gateway   = InternetGateway("#{prefix}-gateway")

    ## Route Table
    public_rt = RouteTable("#{prefix}-public-routing") {
      Route(nil, gateway: gateway)
    }
    private_rt = RouteTable("#{prefix}-private-routing") {
      #Route(nil, gateway: gateway)
    }

    ### Subnet
    public_a  = Subnet("#{prefix}-public-a" , "10.0.1.0/24" , az_a, public_rt)
    public_b  = Subnet("#{prefix}-public-b" , "10.0.2.0/24" , az_b, public_rt)
    public_c  = Subnet("#{prefix}-public-c" , "10.0.3.0/24" , az_c, public_rt)
    private_a = Subnet("#{prefix}-private-a", "10.0.11.0/24", az_a, private_rt)
    private_b = Subnet("#{prefix}-private-b", "10.0.12.0/24", az_b, private_rt)
    private_c = Subnet("#{prefix}-private-c", "10.0.13.0/24", az_c, private_rt)

    ## Security Group
    bastion_server = "#{prefix}-bastion"
    bastion_secgrp = SecurityGroup("#{prefix}-bastion-secgrp", "allows ssh") {
      #Ingress(:any ,    0, :self)
      Ingress(:tcp ,   22, "#{var.office_ip}/32")  # allows ssh only from office ip
      Ingress(:icmp,  nil, [vpc_cidr, "#{var.office_ip}/32"])
      Egress( :any ,    0, nil)
    }
    public_secgrp  = SecurityGroup("#{prefix}-public-secgrp", "allows http,https") {
      Ingress(:any ,    0, :self)
      Ingress(:tcp ,   22, bastion_server)
      Ingress(:tcp ,   80, nil)
      Ingress(:tcp ,  443, nil)
      Ingress(:icmp,  nil, vpc_cidr)
      Egress( :any ,    0, nil)
    }
    private_secgrp = SecurityGroup("#{prefix}-private-secgrp", "deny inbound, allow outbound") {
      Ingress(:any ,    0, :self)
      Ingress(:tcp ,   22, bastion_server)
      Ingress(:tcp , 5432, public_secgrp)   # PostgreSQL port
      Ingress(:icmp,  nil, vpc_cidr)
      Egress( :any ,    0, nil)
    }

    ### EC2 and EIP
    let public_a, bastion_secgrp, ubuntu_ami, bastion_sshkey_name do
      |sn, sg, ami, kn|
      bastion    = EC2(bastion_server   , t3_nano,  ami, sn, sg, kn)
      bastion_ip = EIP("#{prefix}-bastion-ip", bastion)
      public_dns_records  << [:A, "bastion", bastion_ip]
      private_dns_records << [:A, "bastion", bastion]
      output[:bastion_ip] = bastion_ip.attr(:public_ip)
    end
    let public_a, public_secgrp, ubuntu_ami, ec2_sshkey_name do
      |sn, sg, ami, kn|
      www_ec2  = EC2("#{prefix}-www-ec2" , t3_micro, ami, sn, sg, kn)
      www_ip   = EIP("#{prefix}-www-ip"  , www_ec2)
      public_dns_records  << [:A, "www"  , www_ip]
      private_dns_records << [:A, "www"  , www_ec2]
      output[:www_ip] = www_ip.attr(:public_ip)
    end

    ### RDS
    rds_master = nil
    rds_slave  = nil
    let do
      subnetgrp = RDS_SubnetGroup("rds-subnetgrp", [private_a, private_c])
      paramgrp  = RDS_ParameterGroup("pg10-paramgrp", "postgres10", {
        #"rds.log_retention_period"   => 10080,   # = 60min * 24h * 7day
        #"random_page_cost"           => 1.1,
        "work_mem"                   => 16384,   # = 1024KB * 16MB
        "maintenance_work_mem"       => 32768,   # = 1024KB * 32MB
        #"log_filename"               => "postgresql.log.%Y-%m-%d",
        #"log_rotation_age"           => 1440,    # = 60min * 24h
        #"log_lock_waits"             => 1,
        #"log_min_messages"           => "notice",
        #"log_min_duration_statement" => 200,     # msec
        #"log_temp_files"             => 0,
        #"log_connections"            => 1,
        #"log_disconnections"         => 1,
        "shared_preload_libraries!"  => "auto_explain,pg_stat_statements",
        #"auto_explain.log_min_duration" => 200,  # msec
        #"auto_explain.log_format"    => "text",  # text,xml,json,yaml
        #"auto_explain.log_analyze"   => 1,
        #"auto_explain.log_buffers"   => 1,
        #"auto_explain.log_nested_statements" => 1,
        #"pg_stat_statements.save"    => 1,       # default: 1
        #"pg_stat_statements.track"   => "all",   # default: top
        #"pg_stat_statements.max!"    => 1000,    # default: 1000
        #"track_activity_query_size!" => 1024,    # default: 1024
      })
      #optiongrp = RDS_OptionGroup("")
      optiongrp = nil
      #
      rds_master = RDS_Instance("db-master", "db.t2.small")
      let rds_master do |rds|
        rds.database    = {engine: "postgres", version: "10.6",
                           name: nil, port: 5432,
                           user: var.db_user, password: var.db_pass,
                           parameter_group: paramgrp, option_group: optiongrp}
        rds.network     = {subnet_group: subnetgrp,
                           security_group: [private_secgrp],
                           az: az_a, public_access: false, multi_az: false}
        rds.storage     = {type: :general, size: '20GB'}
        rds.encryption  = {enable: false}
        rds.backup      = {days: 14, window: {start: '00:00', hours: 0.5}}
        rds.monitoring  = {interval: 60}  # 60sec
        rds.maintenance = {auto_upgrade: true, maintenace_window: nil}
      end
      output[:rds_master_endpoint] = rds_master.attr(:endpoint)
      #
      rds_slave = RDS_ReadReplica("db-slave", "db.t2.micro", rds_master)
      let rds_slave do |rds|
        rds.database    = {port: 5432}
        rds.network     = {region: region, subnet_group: subnetgrp,
                           az: az_c, public_access: false, multi_az: false}
        rds.storage     = {type: :general, size: '20GB'}
        rds.encryption  = {enable: false}
        rds.monitoring  = {interval: 60}  # 60sec
        rds.maintenance = {auto_upgrade: true}
      end
      output[:rds_slave_endpoint] = rds_slave.attr(:endpoint)
    end#let

  }#vpc

}#region


aws_infra.global {

  Route53() {

    Zone("public-#{app_env}", var.base_domain) {
      s = app_env == "prod" ? "" : "#{app_env}-"
      public_dns_records.each do |type, name, value|
        Record(type, s+name, value)
      end
    }

    PrivateZone("private-#{app_env}", "#{app_env}", vpc) {
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
