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
      @base_url = 'https://api.shodan.io/'
      @base_url_exploits = 'https://exploits.shodan.io/api/'

      @exploits = Exploits.new(self)
    end

    # Internal method that sends out the HTTP request.
    # Expects a webservice function (ex. 'search') name and a hash of arguments.
    def request(type, func, args)
      base_url = if type == 'exploits'
                   @base_url_exploits
                 else
                   @base_url
                 end

      # Convert the argument hash into a string
      args_string = args.map { |k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}" }.join('&')

      # Craft the final request URL
      url = "#{base_url}#{func}?key=#{@api_key}&#{args_string}"

      # Send the request
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      response = http.get(uri.request_uri)

      if type == 'shodan'
        # Convert the JSON data into a native Ruby hash
        data = JSON.parse(response.body)
        # Raise an error if something went wrong
        if data.key? 'error'
          raise data['error']
        end
      else
        data = response.body
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
      request('shodan', "shodan/host/#{ip}", {})
    end

    # Perform a search on Shodan.
    #
    # Arguments:
    # query - search query; same format as the website (string)
    #
    # Returns a hash containing the search results
    def search(query, params = {})
      params[:query] = query
      request('shodan', 'shodan/host/search', params)
    end

    # Find how many results there are for a search term.
    #
    # Arguments:
    # query - search query; same format as the website (string)
    #
    # Returns a hash containing the total number of search results
    def count(query, params = {})
      params[:query] = query
      request('shodan', 'shodan/host/count', params)
    end

    # Returns information about the current API key.
    def info
      request('shodan', 'api-info', {})
    end

    # Returns information about the Shodan Account linked to
    # the current API key.
    def account
      request('shodan', 'account/profile', {})
    end

    # List all protocols that can be used when performing on-demand
    # Internet scans via Shodan.
    # This method returns an object containing all the protocols
    # that can be used when launching an Internet scan.
    def protocols
      request('shodan', 'shodan/protocols', {})
    end

    # List all services that Shodan crawls
    # Returns an object containing all the services
    # that the Shodan crawlers look at. It can also be used as
    # a quick and practical way to resolve a port number to the
    # name of a service.
    def services
      request('shodan', 'shodan/services', {})
    end

    # DNS Lookup
    # Look up the IP address for the provided list of hostnames.
    # Parameters
    # hostnames: [String] Comma-separated list of hostnames;
    # example "google.com,bing.com"
    def resolve(hostnames)
      request('shodan', 'dns/resolve', :hostnames => hostnames)
    end

    # Reverse DNS Lookup
    # Look up the hostnames that have been defined for the
    # given list of IP addresses.
    # Parameters
    # ips: [String] Comma-separated list of IP addresses;
    # example "74.125.227.230,204.79.197.200"
    def reverse(ips)
      request('shodan', 'dns/reverse', :ips => ips)
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
    def search(query, params = {})
      params[:query] = query
      @api.request('exploits', 'search', params)
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
    def count(query, params = {})
      params[:query] = query
      @api.request('exploits', 'count', params)
    end
  end
end
