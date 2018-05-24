require 'active_support'
require 'active_support/core_ext/object'
require 'cgi'
require 'uri'
require 'faraday_middleware'
require 'faraday-manual-cache'
require 'faraday'
require 'openssl'
require 'active_support/cache'

module FatSecret
  class Connection

    class << self
      def faraday_client
        @faraday_client ||= Faraday.new() do |faraday|
          faraday.response :logger
          faraday.response :json
          faraday.adapter  Faraday.default_adapter
        end
      end

      def store
        @store ||= ActiveSupport::Cache.lookup_store(:redis_store, { host: FatSecret.configuration.redis_host, port: FatSecret.configuration.redis_port, db: FatSecret.configuration.redis_db })
      end

      def key(method, params)
        method.to_s + "_" + params.to_s
      end

      def get(method, params)
        cache_key = key(method, params)
        cached = store.fetch(cache_key)
        if cached
          return cached
        end

        FatSecret.configuration.logger.debug(
          "FatSecret::Connection.get #{method} with #{params}"
        )

        params = default_parameters.merge(params).merge(method: method)
        params.each do |key, value|
          params[key] = CGI.escape(value) if value.is_a?(String)
        end
        uri = request_uri('GET', params)
        response = faraday_client.get(uri)
        FatSecret.configuration.logger.debug(
          "FatSecret Response: #{response}"
        )

        store.write(cache_key, response.body, expires_in: FatSecret.configuration.cache_ttl)

        response.body
      end

      private

      def request_uri(http_method, params)
        params.merge!(oauth_signature: generate_signature(http_method, params))
        URI.parse("#{FatSecret.configuration.uri}?#{params.to_param}")
      end

      def generate_signature(http_method, params)
        signature_value(
          [
            CGI.escape(http_method), CGI.escape(FatSecret.configuration.uri),
            CGI.escape(Hash[params.sort].to_query)
          ].join('&')
        )
      end

      def normalized_parameters(params)
        URI.encode(default_parameters.merge(params).sort.to_param)
      end

      def default_parameters
        {
          oauth_consumer_key: FatSecret.configuration.consumer_key,
          oauth_signature_method: 'HMAC-SHA1',
          oauth_timestamp: Time.now.to_i,
          oauth_nonce: SecureRandom.hex(8),
          oauth_version: '1.0',
          format: 'json'
        }
      end

      def signature_value(base_string, access_secret = '')
        digest = OpenSSL::HMAC.digest(
          OpenSSL::Digest.new('sha1'),
          "#{FatSecret.configuration.shared_secret}&#{access_secret}",
          base_string
        )
        Base64.encode64(digest).gsub(/\n/, '')
      end
    end
  end
end
