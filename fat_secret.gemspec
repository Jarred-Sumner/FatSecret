# -*- encoding: utf-8 -*-
require File.expand_path('../lib/fat_secret/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Matt Beedle"]
  gem.email         = ["mattbeedle@googlemail.com"]
  gem.description   = %q{FatSecret API wrapper}
  gem.summary       = %q{FatSecret API wrapper}
  gem.homepage      = "https://github.com/mattbeedle/FatSecret"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "fat_secret"
  gem.require_paths = ["lib"]
  gem.version       = FatSecret::VERSION

  gem.add_dependency('active_attr')
  gem.add_dependency('activesupport')
  gem.add_dependency('faraday')
  gem.add_dependency "faraday_middleware"
  gem.add_dependency('faraday-manual-cache')
  # gem.add_dependency('typhoeus', '~> 0.5.0.rc')
  # gem.add_dependency('yajl-ruby')

  gem.add_development_dependency('fakeweb')
  gem.add_development_dependency('rspec')
  gem.add_development_dependency('vcr')
end
