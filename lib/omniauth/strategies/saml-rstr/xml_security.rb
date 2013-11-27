# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the License). You may not use this file except in
# compliance with the License.
#
# You can obtain a copy of the License at
# https://opensso.dev.java.net/public/CDDLv1.0.html or
# opensso/legal/CDDLv1.0.txt
# See the License for the specific language governing
# permission and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# Header Notice in each file and include the License file
# at opensso/legal/CDDLv1.0.txt.
# If applicable, add the following below the CDDL Header,
# with the fields enclosed by brackets [] replaced by
# your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
#
# $Id: xml_sec.rb,v 1.6 2007/10/24 00:28:41 todddd Exp $
#
# Copyright 2007 Sun Microsystems Inc. All Rights responseerved
# Portions Copyrighted 2007 Todd W Saxton.

require 'rubygems'
require "rexml/document"
require "rexml/xpath"
require "openssl"
require "xmlcanonicalizer"
require "digest/sha1"
require "nokogiri"

module OmniAuth
  module Strategies
    class SAML_RSTR

      module XMLSecurity

        class SecurityTokenResponseContent

          #plugging these namespaces in was required in order to get nokogiri to use them. eg @xml.at_xpath("//ds:SignatureValue", {"ds" => DSIG}).text. Any way to avoid this?
          DSIG      = "http://www.w3.org/2000/09/xmldsig#"
          SAML      = "urn:oasis:names:tc:SAML:1.0:assertion"
          WSP       = "http://schemas.xmlsoap.org/ws/2004/09/policy"
          WSA       = "http://www.w3.org/2005/08/addressing"
          WSU       = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
          TRUST     = "http://schemas.xmlsoap.org/ws/2005/02/trust"

          attr_accessor :name_identifier, :xml, :xml_unnamespaced, :name_identifier_test, :x509_cert, :conditions_not_on_or_after, :conditions_before, :info_element

          def initialize(response)
            self.xml_unnamespaced = Nokogiri::XML::Document.parse(response).remove_namespaces!()
            self.xml = Nokogiri::XML::Document.parse(response)
          end

          def signature
            @xml.at_xpath("//ds:SignatureValue", {"ds" => DSIG}).text
          end

          def info_element
            @xml.at_xpath("//ds:SignedInfo", {"ds" => DSIG})
          end

          def attribute_statement
            @xml_unnamespaced.css('AttributeStatement').css('Attribute').map.each {|a| {name: a.attribute('AttributeName').text, value: a.css('AttributeValue').text}}
          end

          def name_identifier
            @xml_unnamespaced.css("NameIdentifier").text
          end

          def conditions_before
            if !conditions.nil?
              conditions.attribute("NotBefore").value
            end
          end

          def conditions_not_on_or_after
            if !conditions.nil?
              conditions.attribute("NotOnOrAfter").value
            end
          end

          def x509_cert
            @xml_unnamespaced.css("X509Certificate").text
          end

          #validate the response fingerprint matches the plugin fingerprint
          #validate the certificate signature matches the signature generated from signing the certificate's SignedInfo node
          def validate(idp_cert_fingerprint, soft = true)

            cert_text   = Base64.decode64(x509_cert)

            certificate = OpenSSL::X509::Certificate.new(cert_text)
            fingerprint = Digest::SHA1.hexdigest(certificate.to_der)

            config_fingerprint = idp_cert_fingerprint.gsub(/[^a-zA-Z0-9]/,"").downcase
            if fingerprint != config_fingerprint
              raise OmniAuth::Strategies::SAML_RSTR::ValidationError.new("Fingerprint validation error\n expected:\t#{config_fingerprint}\n actual:\t#{fingerprint} ")
            end

            canon_string =  info_element.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
            sig  = Base64.decode64(signature)

            if !certificate.public_key.verify(OpenSSL::Digest::SHA256.new, sig, canon_string)
              return soft ? false : (raise OmniAuth::Strategies::SAML_RSTR::ValidationError.new("Key validation error"))
            end

            return true
          end

          private

          def conditions
            @xml.at_xpath("//saml:Conditions", {"saml" => SAML})
          end

        end

      end

    end
  end
end
