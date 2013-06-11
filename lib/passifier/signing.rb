#!/usr/bin/env ruby

module Passifier

  # Class for Pass signing functionality
  class Signing

    # @param [String] key_pem The key pem file location
    # @param [String] pass_phrase The key pass phrase
    # @param [String] certificate_pem The certificate pem file location
    def initialize(key_pem, pass_phrase, certificate_pem)
      @certificate = File.read(certificate_pem)
      @key = File.read(key_pem)
      @pass_phrase = pass_phrase
    end

    def initialize(p12, pass_phrase)
      @p12 = OpenSSL::PKCS12.new(File.read(p12)), pass_phrase)
    end

    # Generate a digest of the given content
    # @param [String] content The content to generate a digest from
    # @return [String] The resulting digest
    def sha(content)
      signed_contents = sign(content)
      Digest::SHA1.hexdigest(signed_contents)
    end

    # Sign the given content
    # @param [String] content The content to generate a signing of
    # @return [String] The resulting signing
    def sign(content)
      if @p12 then
        key = @p12.key
        certificate = @p12.certificate
      else
        key = OpenSSL::PKey::RSA.new(@key, @pass_phrase)
        certificate = OpenSSL::X509::Certificate.new(@certificate)
      end
      OpenSSL::PKCS7.sign(certificate, key, content, nil, OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOATTR | OpenSSL::PKCS7::DETACHED).to_der
    end

  end

end


