require 'rubygems'
require 'cgi'
require 'json'
require 'net/http'

module Shodan
  
  # The WebAPI class interfaces with the shodanhq.com/api
  # It currently supports 2 methods:
  # 1. search (query)
  # 2. host (ip)
  #
  # Author:: achillean (mailto:jmath at surtri.com)
  #
  # :title:Shodan::WebAPI
  class WebAPI
    attr_accessor :api_key
    attr_accessor :base_url
    
    def initialize(api_key)
      @api_key = api_key
      @base_url = "http://www.shodanhq.com/api/"
    end
    
    # Internal method that sends out the HTTP request.
    # Expects a webservice function (ex. 'search') name and a hash of arguments.
    def request(func, args)
      # Convert the argument hash into a string
      args_string = args.map{|k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v)}"}.join("&")
        
      # Craft the final request URL
      url = "#{@base_url}#{func}?key=#{@api_key}&#{args_string}"
      
      # Send the request
      response = Net::HTTP.get_response(URI.parse(url))
      
      # Convert the JSON data into a native Ruby hash
      data = JSON.parse(response.body)
      
      # Raise an error if something went wrong
      if data.has_key? 'error'
        raise data['error']
      end
      
      return data
    end
    private :request
    
    # Get all available information on an IP.
    #
    # Arguments:
    # ip  - host IP (string)
    #
    # Returns a hash containing the host information
    def host(ip)
      return request('host', {:ip => ip})
    end
    
    # Perform a search on Shodan.
    #
    # Arguments:
    # query - search query; same format as the website (string)
    #
    # Returns a hash containing the search results
    def search(query)
      return request('search', {:q => query})
    end
  end
  
end
