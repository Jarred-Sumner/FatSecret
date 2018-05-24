module FatSecret
  class Config
    attr_accessor :access_key, :consumer_key, :shared_secret, :logger, :redis_host, :cache_ttl, :redis_port, :redis_db

    def uri
      'http://platform.fatsecret.com/rest/server.api'
    end

    def logger
      @logger || Logger.new($STDOUT)
    end
  end
end
