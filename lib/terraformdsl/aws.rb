# -*- coding: utf-8 -*-

require 'json'

require_relative './common'


module TerraformDSL::AWS


  class Resource

    def set_parent(resource)
      @parent.nil?  or raise "already parent set."
      @parent = resource
    end

    attr_reader :parent

    def accept(visitor)
      method = 'on_' + self.class.name.sub(/^.*?AWS::/, '').gsub('::', '_')
      visitor.__send__(method, self) do
        @children.each do |x|
          x.accept(visitor)
        end if @children
      end
    end

    def attr(attr)
      raise NotImplementedError.new("#{self.class.name}#attr(#{attr.inspect}): not available.")
    end

    private

    def add_resource(res, &blk)
      res.set_parent(self)
      (@children ||= []) << res
      res.instance_exec(res, &blk) if blk
      return res
    end

    def let(*args)
      yield *args
    end

  end


  def self.infra(*args, &blk)
    infra = Infra.new(*args)
    infra.instance_exec(infra, &blk) if blk
    @current_infra = infra
    return infra
  end

  def self.current_infra
    @current_infra
  end


  class Infra < Resource

    def region(*a, &b); add_resource(Region.new(*a), &b); end
    def global(*a, &b); add_resource(Global.new(*a), &b); end

    def generate_tf
      visitor = TerraformVisitor.new
      visitor.visit(self)
      tf_str = visitor.output()
      #
      if $_rds_monitoring_role_required
        tf_str << RDS::RDS_MONITORING_ROLE_TF
      end
      #
      return tf_str
    end

  end


  class Global < Resource

    def Route53(*a, &b); add_resource(Route53.new(*a), &b); end
    def IAM    (*a, &b); add_resource(IAM    .new(*a), &b); end

  end


  class Region < Resource

    def initialize(name=nil)
      @name = name
    end
    attr_reader :name

    def AZ (*a, &b); add_resource(AZ .new(*a), &b); end
    def AMI(*a, &b); add_resource(AMI.new(*a), &b); end
    def VPC(*a, &b); add_resource(VPC.new(*a), &b); end

  end


  class AZ < Resource

    def initialize(name)
      @name = name
    end
    attr_reader :name

  end


  class AMI < Resource

    def initialize(name, owners, pattern)
      @name = name
      @owners  = [owners].flatten()
      @pattern = pattern
    end
    attr_reader :name, :owners, :pattern

    def attr(attr); "${data.aws_ami.#{@name}.#{attr}}"; end

  end


  class VPC < Resource

    def initialize(name, cidr)
      @name = name
      @cidr = cidr
    end
    attr_reader :name, :cidr

    def attr(attr); "${aws_vpc.#{@name}.#{attr}}"; end

    def EC2   (*a, &b); add_resource(EC2   .new(*a), &b); end
    def EIP   (*a, &b); add_resource(EIP   .new(*a), &b); end
    def Subnet(*a, &b); add_resource(Subnet.new(*a), &b); end
    def InternetGateway(*a, &b); add_resource(InternetGateway.new(*a), &b); end
    def RouteTable     (*a, &b); add_resource(RouteTable     .new(*a), &b); end
    def SecurityGroup  (*a, &b); add_resource(SecurityGroup  .new(*a), &b); end
    def RDS_SubnetGroup(*a, &b); add_resource(RDS::SubnetGroup.new(*a), &b); end
    def RDS_ParameterGroup(*a, &b); add_resource(RDS::ParameterGroup.new(*a), &b); end
    def RDS_OptionGroup(*a, &b); add_resource(RDS::OptionGroup.new(*a), &b); end
    def RDS_Instance   (*a, &b); add_resource(RDS::Instance  .new(*a), &b); end
    def RDS_ReadReplica(*a, &b); add_resource(RDS::ReadReplica.new(*a), &b); end

  end


  class Subnet < Resource

    def initialize(name, cidr, az, route_table=nil)
      @name = name
      @cidr = cidr
      @az   = az
      @route_table = route_table
    end
    attr_reader :name, :cidr, :az, :route_table

    def attr(attr); "${aws_subnet.#{@name}.#{attr}}"; end

  end


  class InternetGateway < Resource

    def initialize(name)
      @name = name
    end
    attr_reader :name

    def attr(attr); "${aws_internet_gateway.#{@name}.#{attr}}"; end

  end


  class RouteTable < Resource

    def initialize(name)
      @name = name
    end
    attr_reader :name

    def attr(attr); "${aws_route_table.#{@name}.#{attr}}"; end

    def Route(*a, &b); add_resource(Route.new(*a), &b); end

  end


  class Route < Resource

    def initialize(cidr, gateway: nil, ec2: nil, nat: nil, egress_only: nil, network_interface: nil)
      @cidr    = cidr
      @gateway = gateway
      @ec2     = ec2
      @nat     = nat
      @egress_only = egress_only
      @network_interface = network_interface
    end
    attr_reader :cidr, :gateway, :ec2, :nat, :egress_only, :network_interface

    def attr(attr)
      @name  or raise "#{self.class.name}#attr() is not available without name."
      "${aws_route_table.#{@name}.#{attr}}"
    end

  end


  class SecurityGroup < Resource

    def initialize(name, desc)
      @name    = name
      @desc    = desc
    end
    attr_reader :name, :desc

    def attr(attr); "${aws_security_group.#{@name}.#{attr}}"; end

    def Ingress(*a, &b); add_resource(Ingress.new(*a), &b); end
    def Egress (*a, &b); add_resource(Egress .new(*a), &b); end

  end


  class Ingress < Resource

    PROTOCOLS = [:tcp, :udp, :icmp, :any]

    def initialize(protocol, port, destination)
      PROTOCOLS.include?(protocol)  or
        raise ArgumentError.new("#{protocol.inspect}: unknown protocol for Ingress.")
      @protocol    = protocol
      @port        = port
      @destination = destination
    end
    attr_reader :protocol, :port, :destination

  end


  class Egress < Resource

    PROTOCOLS = [:tcp, :udp, :icmp, :any]

    def initialize(protocol, port, destination)
      PROTOCOLS.include?(protocol)  or
        raise ArgumentError.new("#{protocol.inspect}: unknown protocol for Egress.")
      @protocol    = protocol
      @port        = port
      @destination = destination
    end
    attr_reader :protocol, :port, :destination

  end


  class EC2 < Resource

    def initialize(name, type, ami, subnet, security_group, key_name)
      @name     = name
      @type     = type
      @ami      = ami
      @subnet   = subnet
      @security_group = security_group
      @key_name = key_name
    end
    attr_reader :name, :type, :ami, :subnet, :security_group, :key_name

    def cpu_credit
      case @type
      when /^t[2-9]\./ ; "unlimited"
      else             ; nil
      end
    end

    def attr(attr); "${aws_instance.#{@name}.#{attr}}"; end

  end


  class EIP < Resource

    def initialize(name, ec2)
      @name = name
      @ec2  = ec2
    end
    attr_reader :name, :ec2

    def attr(attr); "${aws_eip.#{@name}.#{attr}}"; end

  end


  module RDS

    RDS_MONITORING_ROLE_NAME = "rds-monitoring-role"
    RDS_MONITORING_ROLE_TF = <<END
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

END


    class SubnetGroup < Resource

      def initialize(name, subnets=[])
        subnets.all? {|x| x.is_a?(Subnet) }  or
          raise TypeError.new("RDS::SubnetGroup(#{name.inspect}): 2nd argument should be an array of Subnet, but got: #{subnets.inspect}")
        @name = name
        @subnets = subnets
      end
      attr_reader :name, :subnets

      def attr(attr); "${aws_db_subnet_group.#{@name}.#{attr}}"; end

    end


    class ParameterGroup < Resource

      def initialize(name, family, parameters={})
        @name    = name
        @family  = family
        @parameters = parameters
      end
      attr_reader :name, :family, :parameters

      def attr(attr); "${aws_db_parameter_group.#{@name}.#{attr}}"; end

    end


    class OptionGroup < Resource

      def initialize(name, engine, version)
        @name = name
        @engine = engine
        @version = version
        @options = {}
      end
      attr_reader :name, :engine, :version, :options

      def attr(attr); "${aws_db_option_group.#{@name}.#{attr}}"; end

      def add_option(name, kvs={})
        @options[name] = kvs
        nil
      end

    end


    class Instance < Resource

      def initialize(name, machine_type)
        @name         = name
        @machine_type = machine_type
        @master_instance = nil
        @database     = {}
        @network      = {}
        @flags        = {}
        @storage      = {}
        @encryption   = {}
        @backup       = {}
        @monitoring   = {}
        @maintenance  = {}
      end
      attr_reader :name, :machine_type, :master_instance
      attr_reader :database, :network, :flags, :storage, :encryption, :backup, :monitoring, :maintenance

      def database=(engine: nil, version: nil, license: nil,
                    name: nil, port: 5432, user: nil, password: nil,
                    parameter_group: nil, option_group: nil)
        @database = {engine: engine, version: version, license: license,
                     name: name, port: port, user: user, password: password,
                     parameter_group: parameter_group, option_group: option_group}
      end

      def network=(subnet_group: nil, security_group: [], az: nil, public_access: nil, multi_az: nil)
        @network = {subnet_group: subnet_group, security_group: security_group,
                    az: az, public_access: public_access, multi_az: multi_az}
      end

      def storage=(type: nil, size: nil)
        @storage = {type: type, size: size}
      end

      def encryption=(enable: nil)
        @encryption = {enable: enable}
      end

      def backup=(days: 7, window: nil)
        @backup = {days: days, window: window}
      end

      def monitoring=(interval: nil, role: nil)
        if interval && interval > 0
          role ||= RDS_MONITORING_ROLE_NAME
        end
        @monitoring = {interval: interval, role: role}
      end

      def maintenance=(auto_upgrade: true, maintenace_window: nil)
        @maintenance = {auto_upgrade: auto_upgrade,
                        maintenace_window: maintenace_window}
      end

      def attr(attr); "${aws_db_instance.#{@name}.#{attr}}"; end

    end


    class ReadReplica < Instance

      def initialize(name, machine_type, master_instance)
        super(name, machine_type)
        @master_instance = master_instance
      end

      def database=(port: nil)
        @database = {}
        @database[:port]   = port    unless port.nil?
      end

      def network=(region: nil, subnet_group: nil, az: nil, public_access: nil, multi_az: nil)
        @network = {region: region, subnet_group: subnet_group,
                    az: az, public_access: public_access, multi_az: multi_az}
      end

      def storage=(type: nil, size: nil)
        @storage = {type: type, size: size}
      end

      def encryption=(enable: nil)
        @encryption = {enable: enable}
      end

      def monitoring=(interval: nil, role: nil)
        if interval && interval > 0
          role ||= RDS_MONITORING_ROLE_NAME
        end
        @monitoring = {interval: interval, role: role}
      end

      def maintenance=(auto_upgrade: true, maintenace_window: nil)
        @maintenace = {auto_upgrade: auto_upgrade,
                       maintenace_window: maintenace_window}
      end

      def attr(attr); "${aws_db_instance.#{@name}.#{attr}}"; end

    end


  end


  class Route53 < Resource

    RECORD_TYPES = [
      :A, :AAAA, :CAA, :CNAME, :MX, :NAPTR, :NS,
      :PTR, :SOA, :SPF, :SRV, :TXT,
    ]

    def initialize()
    end

    def Zone       (*a, &b); add_resource(Zone.new(*a)       , &b); end
    def PrivateZone(*a, &b); add_resource(PrivateZone.new(*a), &b); end


    class Zone < Resource

      def initialize(name, domain)
        @name = name
        @domain = domain
      end
      attr_reader :name, :domain

      def attr(attr); "${aws_route53_zone.#{@name}.#{attr}}"; end

      def Record(*a, &b); add_resource(Record.new(*a), &b); end

    end


    class PrivateZone < Resource

      def initialize(name, domain, vpc)
        @name = name
        @domain = domain
        @vpc = vpc
      end
      attr_reader :name, :domain, :vpc

      def attr(attr); "${aws_route53_zone.#{@name}.#{attr}}"; end

      def Record(*a, &b); add_resource(Record.new(*a), &b); end

    end


    class Record < Resource

      def initialize(type, name, values, opts={})
        RECORD_TYPES.include?(type)  or
          raise "#{type.inspect}: unknown record type."
        @type   = type
        @name   = name
        @values = [values].flatten
        @opts   = opts
      end
      attr_reader :type, :name, :values, :opts

      def attr(attr); "${aws_route53_record.#{@name}.#{attr}}"; end

    end


  end


  class IAM < Resource

    def initialize()
    end

    def Role       (*a, &b); add_resource(Role.new(*a)       , &b); end
    def PolicyAttachment(*a, &b); add_resource(PolicyAttachment.new(*a), &b); end


    class Role < Resource

      def initialize(name, path, policy)
        @name     = name
        @path     = path
        @policy   = policy
      end
      attr_reader :name, :path, :policy

      def attr(attr); "${aws_iam_role.#{@name}.#{attr}}"; end

    end


    class PolicyAttachment < Resource

      def initialize(name, groups=[], users=[], roles=[])
        @name     = name
        @groups   = groups
        @users    = users
        @roles    = roles
      end
      attr_reader :name, :groups, :users, :roles

      def attr(attr); "${aws_policy_role.#{@name}.#{attr}}"; end

    end


  end


  class Visitor

    def visit(resource)
      resource.accept(self)
    end

  end


  class TerraformVisitor < Visitor

    def initialize
      @buf = []
    end

    def output
      return @buf.join("")
    end

    def on_Infra(infra)
      yield
    end

    def on_Global(global)
      yield
    end

    def on_Region(region)
      @buf << <<END
provider "aws" {
  #access_key		= "${var.access_key}"
  #secret_key		= "${var.secret_key}"
  region		= "#{region.name}"
}

END
      yield
    end

    def on_AZ(az)
      yield
    end

    def on_AMI(ami)
      owners = ami.owners.map {|x| "\"#{x}\"" }
      @buf << <<END
data "aws_ami" "#{ami.name}" {
  most_recent		= true
  owners                = [#{owners.join(', ')}]
  filter {
    name		= "name"
    values		= ["#{ami.pattern}"]
  }
}

END
      yield
    end

    def on_VPC(vpc)
      @buf << <<END
resource "aws_vpc" "#{vpc.name}" {
  cidr_block		= "#{vpc.cidr}"
  enable_dns_support	= true
  enable_dns_hostnames	= true
  tags {
    Name		= "#{vpc.name}"
  }
}

END
      yield
    end

    def on_InternetGateway(gw)
      @buf << <<END
resource "aws_internet_gateway" "#{gw.name}" {
  vpc_id		= "#{gw.parent.attr(:id)}"
  tags {
    Name		= "#{gw.name}"
  }
}

END
      yield
    end

    def on_Subnet(subnet)
      @buf << <<END
resource "aws_subnet" "#{subnet.name}" {
  vpc_id		= "#{subnet.parent.attr(:id)}"
  availability_zone	= "#{subnet.az.name}"
  cidr_block		= "#{subnet.cidr}"
  tags {
    Name		= "#{subnet.name}"
  }
}

END
      if subnet.route_table
        @buf << <<END
resource "aws_route_table_association" "#{subnet.route_table.name}-#{subnet.name}" {
  route_table_id	= "#{subnet.route_table.attr(:id)}"
  subnet_id		= "#{subnet.attr(:id)}"
}

END
      end
      yield
    end

    def on_RouteTable(route_table)
      @buf << <<END
resource "aws_route_table" "#{route_table.name}" {
  vpc_id		= "#{route_table.parent.attr(:id)}"
  tags {
    Name		= "#{route_table.name}"
  }
END
      yield
      @buf << <<END
}

END
    end

    def on_Route(route)
      @buf << <<END
  route {
    cidr_block		= "#{route.cidr || '0.0.0.0/0'}"
    gateway_id		= "#{route.gateway.attr(:id)}"
  }
END
      yield
    end

    def on_SecurityGroup(sg)
      @buf << <<END
resource "aws_security_group" "#{sg.name}" {
  name			= "#{sg.name}"
  description		= "#{sg.desc}"
  vpc_id		= "#{sg.parent.attr(:id)}"
  tags {
    Name		= "#{sg.name}"
  }
END
      yield
      @buf << <<END
}

END
    end

    def on_Ingress(ingress, &blk)
      _on_anygress('ingress', ingress, &blk)
    end

    def on_Egress(egress, &blk)
      _on_anygress('egress', egress, &blk)
    end

    def _on_anygress(kind, x, &blk)
      port     = x.port || "-1"
      protocol = x.protocol
      protocol = "-1" if protocol == :any || protocol.nil?
      cidrs    = []
      secgrps  = []
      flag_self = false
      [x.destination].flatten.each {|t|
        case t
        when nil          ; cidrs << "0.0.0.0/0"
        when :any         ; cidrs << "0.0.0.0/0"
        when :self        ; flag_self = true
        when /^\d+\./     ; cidrs << t
        when EC2          ; cidrs << "#{t.attr(:private_ip)}/32"
        when SecurityGroup; secgrps << t.attr(:id)
        when /^\w[-\w]*$/ ; cidrs << "${aws_instance.#{t}.private_ip}/32"
        else              ; cidrs << t
        end
      }
      cidrs_s   = cidrs.map {|s| "\"#{s}\"" }.join(", ")
      secgrps_s = secgrps.map {|s| "\"#{s}\"" }.join(", ")
      @buf <<  "  #{kind} {\n"
      @buf <<  "    from_port		= \"#{port}\"\n"
      @buf <<  "    to_port		= \"#{port}\"\n"
      @buf <<  "    protocol		= \"#{protocol}\"\n"
      @buf <<  "    cidr_blocks		= [#{cidrs_s}]\n" if ! cidrs_s.empty?
      @buf <<  "    security_groups	= [#{secgrps_s}]\n" if ! secgrps.empty?
      @buf <<  "    self		= true\n" if flag_self
      @buf <<  "  }\n"
      yield
    end
    private :_on_anygress

    def on_EC2(ec2)
      sg_s = [ec2.security_group].flatten.collect {|sg|
        "\"#{sg.attr(:id)}\""
      }.join(", ")
      @buf << <<END
resource "aws_instance" "#{ec2.name}" {
  instance_type		= "#{ec2.type}"
  ami			= "#{ec2.ami.attr(:image_id)}"
  subnet_id		= "#{ec2.subnet.attr(:id)}"
  vpc_security_group_ids	= [#{sg_s}]
  key_name		= "#{ec2.key_name}"
END
      if ec2.cpu_credit
        @buf << <<END
  credit_specification {
    cpu_credits		= "#{ec2.cpu_credit}"
  }
END
      end
      @buf << <<END
  tags {
    Name		= "#{ec2.name}"
  }
}

END
      yield
    end

    def on_EIP(eip)
      @buf << <<END
resource "aws_eip" "#{eip.name}" {
  vpc			= true
  instance		= "#{eip.ec2.attr(:id)}"
  tags {
    Name		= "#{eip.name}"
  }
}

END
      yield
    end

    def on_RDS_SubnetGroup(subnetgrp)
      grp = subnetgrp
      ids = grp.subnets.map {|x| "\"#{x.attr(:id)}\"" }
      @buf << <<END
resource "aws_db_subnet_group" "#{grp.name}" {
  name			= "#{grp.name}"
  subnet_ids		= [#{ids.join(', ')}]
  tags {
    Name		= "#{grp.name}"
  }
}

END
      yield
    end

    def on_RDS_ParameterGroup(parametergrp)
      grp = parametergrp
      @buf << <<END
resource "aws_db_parameter_group" "#{grp.name}" {
  name			= "#{grp.name}"
  family		= "#{grp.family}"
END
      grp.parameters.each do |k, v|
        pending_reboot = false
        if k.end_with?('!')
          pending_reboot = true
          k = k.sub(/!$/, '')
        end
        @buf << "  parameter {\n"
        @buf << "    name	= \"#{k}\"\n"
        @buf << "    value	= \"#{v}\"\n"
        @buf << "    apply_method = \"pending-reboot\"\n" if pending_reboot
        @buf << "  }\n"
      end
      @buf << <<END
}

END
      yield
    end

    def on_RDS_OptionGroup(optiongrp)
      grp = optiongrp
      @buf << <<END
resource "aws_db_option_group" "#{grp.name}" {
  name			= "#{grp.name}"
  engine_name		= "#{grp.engine}"
  major_engine_version	= "#{grp.version}"
END
      grp.options.each do |name, kvs|
        @buf << <<END
  option {
    option_name	= "#{name}"
END
        kvs.each do |k, v|
          @buf << <<END
    option_settings {
      name	= "#{k}"
      value	= "#{v}"
    }
END
        end if kvs
        @buf << <<END
  }
END
      end
      @buf << <<END
}

END
      yield
    end

    def on_RDS_Instance(instance)
      x = instance
      storage_type = {general: 'gp2', iops: 'io1', magnetic: 'standard'}
      d = x.backup ? x.backup[:window] : nil
      backup_window = d ? "#{d[:start]}-#{d[:start].sub(/:00$/, ':30')}" : nil
      sg = (x.master_instance || x).network[:security_group] \
             &.map {|g| "\"#{g.attr(:id)}\"" }&.join(", ")
      monitoring_role_arn = \
        case x.monitoring[:role]
        when nil      ; nil
        when String   ; "${aws_iam_role.#{x.monitoring[:role]}.arn}"
        when IAM::Role; "#{x.monitoring[:role].attr(:arn)}"
        else ; raise "#{x.monitoring[:role].inspect}: unexpected value"
        end
      if x.monitoring[:role] == RDS::RDS_MONITORING_ROLE_NAME
        $_rds_monitoring_role_required = true
      end
      str = <<END
resource "aws_db_instance" "#{x.name}" {
  allocated_storage	= "#{x.storage[:size].to_i}"
  auto_minor_version_upgrade	= "#{x.maintenance[:auto_upgrade]}"
  availability_zone	= "#{x.network[:az].name}"
  backup_retention_period	= "#{x.backup[:days]}"
  backup_window		= "#{backup_window}"
  copy_tags_to_snapshot	= "true"
  db_subnet_group_name	= "#{x.master_instance ? nil : x.network[:subnet_group].name}"
  #enabled_cloudwatch_logs_exports = ""
  engine		= "#{x.database[:engine]}"
  engine_version	= "#{x.database[:version]}"
  #final_snapshot_identifier		= ""
  #iam_database_authentication_enabled	= ""
  identifier		= "#{x.name}"
  #identifier_prefix	= ""
  instance_class	= "#{x.machine_type}"
  iops			= "#{x.storage[:iops]}"
  kms_key_id		= "#{x.encryption[:kms_key_id]}"
  license_model		= "#{x.database[:license]}"
  maintenance_window	= "#{x.maintenance[:window]}"
  monitoring_interval	= "#{x.monitoring[:interval]}"
  monitoring_role_arn	= "#{monitoring_role_arn}"
  multi_az		= "#{x.network[:multi_az]}"
  name			= "#{x.database[:name]}"
  option_group_name	= "#{x.database[:option_group]&.name}"
  parameter_group_name	= "#{(x.master_instance || x).database[:parameter_group]&.name}"
  password		= "#{x.database[:password]}"
  port			= "#{x.database[:port]}"
  publicly_accessible	= "#{x.network[:public_access]}"
  replicate_source_db	= "#{x.master_instance&.attr(:id)}"
  #skip_final_snapshot	= ""
  #snapshot_identifier	= ""
  storage_encrypted	= "#{x.encryption[:enable]}"
  storage_type		= "#{storage_type[x.storage[:type]]}"
  #timezone		= "UTC"
  username		= "#{x.database[:user]}"
  vpc_security_group_ids	= [#{sg}]
  #s3_import		= ""
  #tags			= {
  #  Name		= "#{x.name}"
  #}
}

END
      str = str.gsub(/^.*""\n/, '')
      @buf << str
      yield
    end

    def on_RDS_ReadReplica(instance, &block)
      on_RDS_Instance(instance, &block)
    end

    def on_Route53(route53)
      yield
    end

    def on_Route53_Zone(zone)
      @buf << <<END
resource "aws_route53_zone" "#{zone.name}" {
  name			= "#{zone.domain}"
  tags {
    Name		= "#{zone.name}"
  }
}

END
      yield
    end

    def on_Route53_PrivateZone(zone)
      @buf << <<END
resource "aws_route53_zone" "#{zone.name}" {
  name			= "#{zone.domain}"
  vpc {
    vpc_id		= "#{zone.vpc.attr(:id)}"
  }
  tags {
    Name		= "#{zone.name}"
  }
}

END
      yield
    end

    def on_Route53_Record(record)
      values_s = record.values.flatten.collect {|x|
        case x
        when String; "\"#{x}\""
        when EIP   ; "\"#{x.attr(:public_ip)}\""
        when EC2   ; "\"#{x.attr(:private_ip)}\""
        else
          raise TypeError.new("#{x.inspect}: ip address (string, EIP or EC2) expected")
        end
      }.join(", ")
      record_name = record.name.gsub(/[^-\w]/, '_')
      @buf << <<END
resource "aws_route53_record" "#{record.parent.name}-#{record_name}-#{record.type}" {
  zone_id		= "#{record.parent.attr(:zone_id)}"
  type			= "#{record.type}"
  name			= "#{record.name}"
  ttl			= "#{record.opts[:ttl] || 5}"
  records		= [#{values_s}]
}

END
      yield
    end

    def on_IAM(route53)
      yield
    end

    def on_IAM_Role(role)
      json_str = JSON.pretty_generate(role.policy)#.sub(/\n\z/, '')
      @buf << <<END
resource "aws_iam_role" "#{role.name}" {
  name			= "#{role.name}"
  path			= "#{role.path}"
  assume_role_policy	= <<POLICY
#{json_str}
POLICY
}

END
      yield
    end

    def on_IAM_PolicyAttachment(pa)
      groups_str = pa.groups.map {|x| "\"#{x.name}\"" }.join(', ')
      users_str  = pa.users.map  {|x| "\"#{x.name}\"" }.join(', ')
      roles_str  = pa.roles.map  {|x| "\"#{x.name}\"" }.join(', ')
      @buf << <<END
resource "aws_iam_policy_attachment" "#{pa.name}-policy-attachment" {
  name			= "#{pa.name}-policy-attachment"
  policy_arn		= "arn:aws:iam::aws:policy/service-role/#{pa.name}"
  groups		= [#{groups_str}]
  users			= [#{users_str}]
  roles			= [#{roles_str}]
}

END
      yield
    end

  end


end
