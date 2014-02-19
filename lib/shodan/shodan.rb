require 'rubygems'
require 'cgi'
require 'json'
require 'openssl'
require 'net/http'

module Shodan
  
  # The Shodan class interfaces with the official Shodan API.
  # For more information on the API, please visit https://developer.shodan.io
  #
  # Author:: achillean (mailto:jmath@shodan.io)
  #
  # :title:Shodan::Shodan
  class Shodan
    attr_accessor :api_key
    attr_accessor :base_url
    attr_accessor :exploits
    
    def initialize(api_key)
      @api_key = api_key
      @base_url = "https://api.shodan.io/"
      @base_url_exploits = "https://exploits.shodan.io/api/"

      @exploits = Exploits.new(self)
    end
    
    # Internal method that sends out the HTTP request.
    # Expects a webservice function (ex. 'search') name and a hash of arguments.
    def request(type, func, args)
      if type == "exploits"
        base_url = @base_url_exploits
      else
        base_url = @base_url
      end

      # Convert the argument hash into a string
      args_string = args.map{|k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}"}.join("&")
        
      # Craft the final request URL
      url = "#{base_url}#{func}?key=#{@api_key}&#{args_string}"
      
      # Send the request
      puts url
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      response = http.get(uri.request_uri)
      
      # Convert the JSON data into a native Ruby hash
      data = JSON.parse(response.body)
      
      # Raise an error if something went wrong
      if data.has_key? 'error'
        raise data['error']
      end
      
      return data
    end
    
    # Get all available information on an IP.
    #
    # Arguments:
    # ip  - host IP (string)
    #
    # Returns a hash containing the host information
    def host(ip)
      return request('shodan', "shodan/host/#{ip}", {})
    end
    
    # Perform a search on Shodan.
    #
    # Arguments:
    # query - search query; same format as the website (string)
    #
    # Returns a hash containing the search results
    def search(query, params={})
      params[:query] = query
      return request('shodan', 'shodan/host/search', params)
    end
    
    # Find how many results there are for a search term.
    #
    # Arguments:
    # query - search query; same format as the website (string)
    #
    # Returns a hash containing the total number of search results
    def count(query, params={})
      params[:query] = query
      return request('shodan', 'shodan/host/count', params)
    end
    
    # Returns information about the current API key.
    def info()
      return request('shodan', 'api-info', {})
    end
  end
  
  # The Exploits class shouldn't be used independently,
  # as it depends on the Shodan class.
  #
  # Author:: achillean (mailto:jmath@shodan.io)
  #
  # :title:Shodan::Exploits
  class Exploits
    attr_accessor :api
    
    def initialize(api)
      @api = api
    end
    
    # Search the Shodan Exploits archive for exploits.
    #    
    # Arguments:
    # query     -- Search terms
    #
    # Optional arguments:
    # facets    -- A comma-separated list of properties to get summary information on.
    # page      -- The page number to page through results 100 exploits at a time.
    #
    # Returns:
    # A dictionary with 2 main items: matches (list) and total (int).
    # Please visit https://developer.shodan.io/api/exploit-specification for up-to-date information on what an Exploit result contains.
    def search(query, params={})
      params[:query] = query
      return @api.request('exploits', 'search', params)
    end
    
    # Search the Shodan Exploits archive for exploits but don't return results, only the number of matches.
    #    
    # Arguments:
    # query     -- Search terms
    #
    # Optional arguments:
    # facets    -- A comma-separated list of properties to get summary information on.
    #
    # Returns:
    # A dictionary with 1 main item: total (int).
    def count(query, params={})
      params[:query] = query
      return @api.request('exploits', 'count', params)
    end
    
  end
  
end
