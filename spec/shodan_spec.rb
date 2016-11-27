require 'spec_helper'

api = Shodan::Shodan.new(ENV['SHODAN_KEY'])

describe Shodan do
  it 'API has a version number' do
    expect(Shodan::VERSION).not_to be nil
  end
end

describe Shodan, '#apiinfo' do
  it 'API key has a valid plan' do
    expect api.info.key? 'plan'
  end
end

describe Shodan, '#apihost' do
  it 'API Host lookup' do
    test_ip = '8.8.8.8'
    host = api.host(test_ip)
    expect(host['ip_str']).to eq(test_ip)
  end
end

describe Shodan, '#apisearch' do
  it 'API Search Term' do
    term = 'OpenSSH'
    search = api.search(term)
    expect(search['total']).to be > 100
  end
end

describe Shodan, '#apicount' do
  it 'API Search Term Count' do
    term = 'OpenSSH'
    count = api.count(term)
    expect(count['total']).to be > 100
  end
end

describe Shodan, '#apiaccount' do
  it 'API Lookup Account' do
    account = api.account
    expect(account['member']).to be(true)
  end
end

describe Shodan, '#apiprotocols' do
  it 'API List Protocols' do
    protocols = api.protocols
    expect(protocols['bgp']).to eq('Checks whether the device is running BGP.')
  end
end

describe Shodan, '#apiservices' do
  it 'API List Services' do
    services = api.services
    expect(services['21']).to eq('FTP')
  end
end

describe Shodan, '#apiresolve' do
  it 'API Resolve Hostname' do
    host = 'google-public-dns-a.google.com'
    host_ip = '8.8.8.8'
    resolve = api.resolve(host)
    expect(resolve[host]).to eq(host_ip)
  end
end

describe Shodan, '#apireverse' do
  it 'API Reverse Lookup' do
    host = 'google-public-dns-a.google.com'
    host_ip = '8.8.8.8'
    reverse = api.reverse(host_ip)
    expect(reverse[host_ip]).to include(host)
  end
end
