Visit the official Shodan API documentation at:

[https://developer.shodan.io](https://developer.shodan.io)

## Installation

To install the library use rubygems:

	gem install shodan

## Usage

Before you can use the API, you need to have an API key.

[Get your API key here](http://www.shodanhq.com/api_doc)

Setup the Shodan wrapper object:

	require 'shodan'
	
	api = Shodan::Shodan.new(MY_API_KEY)

Print a list of cisco-ios devices:

	result = api.search("cisco-ios")
	result['matches'].each{ |host|
		puts host['ip_str']
	}

Print the 2nd page of results for the cisco-ios query:

	result = api.search("cisco-ios", :page => 2)
	result['matches'].each{ |host|
		puts host['ip_str']
	}

Find out how many results there are for "apache" and also return the top 5 organizations for the results:

	result = api.count("apache", :facets => 'org:5')
	puts "Total number of results: #{result['total']}"
	puts result['facets']

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
