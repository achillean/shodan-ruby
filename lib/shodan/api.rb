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
    attr_accessor :dataloss
    attr_accessor :exploitdb
    attr_accessor :msf
    
    def initialize(api_key)
      @api_key = api_key
      @base_url = "http://www.shodanhq.com/api/"
      @dataloss = DatalossDB.new(self)
      @exploitdb = ExploitDB.new(self)
      @msf = Msf.new(self)
    end
    
    # Internal method that sends out the HTTP request.
    # Expects a webservice function (ex. 'search') name and a hash of arguments.
    def request(func, args)
      # Convert the argument hash into a string
      args_string = args.map{|k, v| "#{CGI.escape(k.to_s)}=#{CGI.escape(v.to_s)}"}.join("&")
        
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
    def search(query, params={})
      params[:q] = query
      return request('search', params)
    end
    
    # Find how many results there are for a search term.
    #
    # Arguments:
    # query - search query; same format as the website (string)
    #
    # Returns a hash containing the total number of search results
    def count(query)
      return request('count', {:q => query})
    end
    
    # Get a greater list of all cities and countries where the devices
    # are located.
    #
    # Arguments:
    # query - search query; same format as the website (string)
    #
    # Returns a hash containing the search results
    def locations(query)
      return request('locations', {:q => query})
    end
    
    # Returns information about the current API key.
    def info(query)
      return request('info', {})
    end
  end
  
  # The DatalossDB class shouldn't be used independently,
  # as it depends on the WebAPI class.
  #
  # Author:: achillean (mailto:jmath at surtri.com)
  #
  # :title:Shodan::DatalossDB
  class DatalossDB
    attr_accessor :api
    
    def initialize(api)
      @api = api
    end
    
    # Search the Dataloss DB archive.
    #
    # Arguments:
    # name          -- Name of the affected company/ organisation
    # 
    # arrest        -- whether the incident resulted in an arrest
    # breaches      -- the type of breach that occurred (Hack, MissingLaptop etc.)
    # country       -- country where the incident took place
    # ext           -- whether an external, third party was affected
    # ext_names     -- the name of the third party company that was affected
    # lawsuit       -- whether the incident resulted in a lawsuit
    # records       -- the number of records that were lost/ stolen
    # recovered     -- whether the affected items were recovered
    # sub_types     -- the sub-categorization of the affected company/ organization
    # source        -- whether the incident occurred from inside or outside the organization
    # stocks        -- stock symbol of the affected company
    # types         -- the basic type of organization (government, business, educational)
    # uid           -- unique ID for the incident
    def search(params={})
      return @api.request('datalossdb/search', params)
    end
    
  end
  
  # The ExploitDB class shouldn't be used independently,
  # as it depends on the WebAPI class.
  #
  # Author:: achillean (mailto:jmath at surtri.com)
  #
  # :title:Shodan::ExploitDB
  class ExploitDB
    attr_accessor :api
    
    def initialize(api)
      @api = api
    end
    
    # Download the exploit code from the ExploitDB archive.
    # 
    # Arguments:
    # id    -- ID of the ExploitDB entry
    # 
    # Returns:
    # A hash with the following fields:
    # filename        -- Name of the file
    # content-type    -- Mimetype
    # data            -- Contents of the file
    def download(id)
      return @api.request('exploitdb/download', {:id => "#{id}"})
    end
    
    # Search the ExploitDB archive.
    #    
    # Arguments:
    # query     -- Search terms
    #
    # Optional arguments:
    # author    -- Name of the exploit submitter
    # platform  -- Target platform (e.g. windows, linux, hardware etc.)
    # port      -- Service port number
    # type      -- Any, dos, local, papers, remote, shellcode and webapps
    #
    # Returns:
    # A dictionary with 2 main items: matches (list) and total (int).
    # Each item in 'matches' is a dictionary with the following elements:
    #
    # id
    # author
    # date
    # description
    # platform
    # port
    # type
    def search(query, params={})
      params[:q] = query
      return @api.request('exploitdb/search', params)
    end
    
  end
  
  # The Msf class shouldn't be used independently,
  # as it depends on the WebAPI class.
  #
  # Author:: achillean (mailto:jmath at surtri.com)
  #
  # :title:Shodan::Msf
  class Msf
    attr_accessor :api
    
    def initialize(api)
      @api = api
    end

    # Download a metasploit module given the fullname (id) of it.
    #
    # Arguments:
    # id        -- fullname of the module (ex. auxiliary/admin/backupexec/dump)
    # 
    # Returns:
    # A dictionary with the following fields:
    # # filename        -- Name of the file
    # content-type    -- Mimetype
    # data            -- File content
    def download(id)
      return @api.request('msf/download', {:id => "#{id}"})
    end
    
    # Search for a metasploit module
    def search(query, params={})
      params[:q] = query
      return @api.request('msf/search', params)
    end
    
  end
  
end
