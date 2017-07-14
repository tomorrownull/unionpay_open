module UnionpayOpen
  Base = Class.new do
    class << self

      def faraday
        Faraday.new(@@endpoint, :ssl => {:verify => false})
      end

      def sign(data)
        Base64.strict_encode64(
          @@pkcs12.key.sign(OpenSSL::Digest::SHA1.new,
                            Digest::SHA1.hexdigest(data)) )
      end
      
      def public_key_sign(data)
                Base64.strict_encode64(
          @@x509_certificate.key.sign(OpenSSL::Digest::SHA1.new,
                            Digest::SHA1.hexdigest(data)) )
      end  

      def global_fixed_params
        { version: '5.0.0',
          encoding: 'UTF-8',
          txnTime: Time.now.strftime("%Y%m%d%H%M%S"),
          certId: @@pkcs12.certificate.serial.to_s,
          merId: @@merchant_no }
      end
      
      def verify?(request)
        verify_params = request.request_parameters.except(:signature).sort.map{ |k, v| "#{k}=#{v}" }.join('&')
        request.request_parameters[:signature]==self.public_key_sign(verify_params)
      end

    end
  end
end
