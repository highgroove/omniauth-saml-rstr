require "time"

module OmniAuth
  module Strategies
    class SAML_RSTR
      class AuthResponse

        ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
        PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"
        DSIG      = "http://www.w3.org/2000/09/xmldsig#"

        attr_accessor :options, :response, :security_token_content, :settings

        def initialize(response, options = {})
          raise ArgumentError.new("Response cannot be nil") if response.nil?
          self.options  = options
          self.response = response
          self.security_token_content = OmniAuth::Strategies::SAML_RSTR::XMLSecurity::SecurityTokenResponseContent.new(response)
        end

        def valid?
          validate(soft = true)
        end

        def validate!
          validate(soft = false)
        end

        def response_params
          @security_token_content.attribute_statement
        end

        # The value of the user identifier as designated by the initialization request response
        def name_id
          @security_token_content.name_identifier
        end

        # A hash of all the attributes with the response. Assuming there is only one value for each key
        def attributes
          { :userEmailID => @security_token_content.name_identifier}
        end

        # When this user session should expire at latest
        def session_expires_at
           @expires_at ||= begin
             parse_time(security_token_content.conditions_not_on_or_after)
           end
        end

        # Conditions (if any) for the assertion to run
        def conditions
          @conditions ||= begin
             {
              :before =>  security_token_content.conditions_before,
              :not_on_or_after => security_token_content.conditions_not_on_or_after
             }
          end
        end

        private

        def validation_error(message)
          raise OmniAuth::Strategies::SAML_RSTR::ValidationError.new(message)
        end

        def validate(soft = true)
           status = validate_response_state(soft) && security_token_content.validate(get_fingerprint, soft)
           return status
        end

        def validate_response_state(soft = true)
          if response.empty?
            return soft ? false : validation_error("Blank response")
          end

          if settings.nil?
            return soft ? false : validation_error("No settings on response")
          end

          if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
            return soft ? false : validation_error("No fingerprint or certificate on settings")
          end
          true
        end

        def get_fingerprint
          if settings.idp_cert
            cert = OpenSSL::X509::Certificate.new(settings.idp_cert.gsub(/^ +/, ''))
            Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(":")
          else
            settings.idp_cert_fingerprint
          end
        end

        def validate_conditions(soft = true)
          return true if conditions.nil?
          return true if options[:skip_conditions]

          if not_before = parse_time(security_token_content.conditions_before)
            if Time.now.utc < not_before
              return soft ? false : validation_error("Current time is earlier than NotBefore condition")
            end
          end

          if not_on_or_after = parse_time(security_token_content.conditions_not_on_or_after)
            if Time.now.utc >= not_on_or_after
              return soft ? false : validation_error("Current time is on or after NotOnOrAfter condition")
            end
          end

          true
        end
        
        private

        def parse_time(attribute)
            Time.parse(attribute)
        end

        def strip(string)
          return string unless string
          string.gsub(/^\s+/, '').gsub(/\s+$/, '')
        end

        def signed_element_id
          doc_id = security_token_content.signed_element_id
          doc_id[1, doc_id.size]
        end
      end
    end
  end
end
