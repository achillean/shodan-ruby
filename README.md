## Installation

To install the library use rubygems:

	gem install shodan

## Usage

Before you can use the API, you need to have an API key.

[Get your API key here](http://www.shodanhq.com/api_doc)

Setup the SHODAN WebAPI:

	require 'shodan'
	
	api = Shodan::WebAPI.new(MY_API_KEY)

Print a list of cisco-ios devices:

	result = api.search("cisco-ios")
	result['matches'].each{ |host|
		puts host['ip']
	}

Get all the information SHODAN has on the IP 217.140.75.46:

	host = api.host('217.140.75.46')
	puts host.to_s

To properly handle potential errors, you should wrap all requests in a try/except block:

	begin
		api.search("cisco-ios")
	rescue Exception => e
		puts "Error: #{e.to_s}"
	else
		puts "Unknown error"
	end
