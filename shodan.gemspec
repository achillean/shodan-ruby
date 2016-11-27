$LOAD_PATH.unshift 'lib'
require 'shodan/version'

Gem::Specification.new do |s|
  s.name              = 'shodan'
  s.version           = Shodan::VERSION
  s.date              = Time.now.strftime('%Y-%m-%d')
  s.summary           = 'A Ruby library to interact with the Shodan API.'
  s.homepage          = 'http://github.com/achillean/shodan-ruby'
  s.email             = 'jmath@shodan.io'
  s.authors           = ['John Matherly']

  s.files             = %w(README.md LICENSE HISTORY.md)
  s.files            += Dir.glob('lib/**/*')

  s.extra_rdoc_files  = ['LICENSE', 'README.md']
  s.rdoc_options      = ['--charset=UTF-8']

  s.description = <<description
  A Ruby library to interact with the Shodan API.
description
end
