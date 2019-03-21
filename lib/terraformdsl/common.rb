# -*- coding: utf-8 -*-

module TerraformDSL


  class Variables

    def initialize(names=[])
      @vars = {}
      names.each do |k|
        k = k.intern if k.is_a?(String)
        @vars[k] = Var.new(k)
      end
    end

    def define(name, desc=nil, default: nil)
      name = name.intern if name.is_a?(String)
      @vars[name] = Var.new(name, desc, default: default)
    end

    def method_missing(name, *args)
      args.empty?  or super
      @vars.key?(name)  or super
      return @vars[name]
    end

    def generate_tf()
      buf = []
      @vars.each do |k, v|
        buf << v.generate_tf()
      end
      buf << "\n"
      return buf.join("")
    end

    #def self.load_tfvars(__filename)
    #  eval File.read(__filename)
    #  __d = local_variables().inject({}) {|d, k|
    #    d[k] = nil unless k.start_with?('__')
    #    d
    #  }
    #  return self.new(__d)
    #end

    def self.load_tf(filename)
      content = File.read(filename)
      rexp = /^[ \t]*variable[ \t]+"([^"]+)"/
      names = []; content.scan(rexp) { names << $1 }
      return self.new(names)
    end

  end


  class Var

    def initialize(name, desc=nil, default: nil)
      name = name.intern if name.is_a?(String)
      @name = name
      @desc = desc
      @default = default
    end
    attr_reader :name, :desc, :default

    def to_s
      "${var.#{@name}}"
    end

    def generate_tf
      k = @name; v = @default; d = @desc
      tf = "variable %-18s {" % "\"#{k}\""
      tf << "\n"                                 if ! v.nil? || ! d.nil?
      tf << "  description = #{d.inspect}\n" if ! d.nil?
      tf << "  default = #{v.inspect}\n"     if ! v.nil?
      tf << "}\n"
      return tf
    end

    def inspect
      to_s()
    end

  end


  class Outputs

    def initialize
      @dict = {}
    end

    def define(key, val)
      @dict[key] = val
    end

    alias []= define

    def generate_tf
      tf = ""
      @dict.each do |k, v|
        tf << "output \"#{k}\" {\n"
        tf << "  value = \"#{v}\"\n"
        tf << "}\n"
        tf << "\n"
      end
      return tf
    end

  end


end
