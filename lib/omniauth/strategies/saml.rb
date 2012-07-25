require 'omniauth'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy

      autoload :AuthRequest,      'omniauth/strategies/saml/auth_request'
      autoload :AuthResponse,     'omniauth/strategies/saml/auth_response'
      autoload :ValidationError,  'omniauth/strategies/saml/validation_error'
      autoload :XMLSecurity,      'omniauth/strategies/saml/xml_security'

      option :name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      def request_phase
        request = OmniAuth::Strategies::SAML::AuthRequest.new
        redirect(request.create(options))
      end

      def callback_phase
        begin

          puts "request---->"
          puts request.inspect
          puts "request.wresult:::::---->"
          puts request.params['wresult']
          response = OmniAuth::Strategies::SAML::AuthResponse.new(request.params['wresult'])
          response.settings = options
          @name_id  = response.name_id
          puts "name id = " + @name_id
          @attributes = response.attributes

          return fail!(:invalid_ticket, 'Invalid SAML Ticket') if @name_id.nil? || @name_id.empty? || !response.valid?
          super
        rescue ArgumentError => e
          fail!(:invalid_ticket, 'Invalid SAML Response')
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @name_id
        }
      end

      extra { { :raw_info => @attributes } }

    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
