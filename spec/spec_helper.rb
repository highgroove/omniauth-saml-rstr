require 'simplecov'
SimpleCov.start
require 'omniauth-saml-rstr'
require 'rack/test'
require 'rexml/document'
require 'rexml/xpath'
require 'base64'
require File.expand_path('../shared/validating_method.rb', __FILE__)

RSpec.configure do |config|
  config.include Rack::Test::Methods
end

def load_xml(filename=:rstr_response)
  filename = File.expand_path(File.join('..', 'support', "#{filename.to_s}.xml"), __FILE__)
  result = IO.read(filename)
end