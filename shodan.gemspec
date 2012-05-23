$LOAD_PATH.unshift 'lib'
require 'shodan/version'

Gem::Specification.new do |s|
  s.name              = "shodan"
  s.version           = Shodan::Version
  s.date              = Time.now.strftime('%Y-%m-%d')
  s.summary           = "A Ruby library to interact with the SHODAN API."
  s.homepage          = "http://github.com/achillean/shodan-ruby"
  s.email             = "jmath@surtri.com"
  s.authors           = [ "John Matherly" ]

  s.files             = %w( README.md LICENSE HISTORY.md )
  s.files            += Dir.glob("lib/**/*")

  s.extra_rdoc_files  = [ "LICENSE", "README.md" ]
  s.rdoc_options      = ["--charset=UTF-8"]

  s.add_dependency "json",            ">= 1.4.6"

  s.description = <<description
  A Ruby library to interact with the SHODAN API.
description
end
