require File.dirname(__FILE__) + '/spec_helper'

describe Shodan::Shodan do
  it "should do nothing" do
    true.should == true
  end

  describe '#base_url_for' do
    subject { Shodan::Shodan.new(nil) }
    it { expect(subject.base_url_for(:exploits)).to eq(Shodan::BASE_URL[:exploits]) }
    it { expect(subject.base_url_for(:main)).to eq(Shodan::BASE_URL[:main]) }
    it { expect(subject.base_url_for(nil)).to eq(Shodan::BASE_URL[:main]) }
  end

  describe '#convert_args_to_string' do
    subject { Shodan::Shodan.new(nil) }
    it { expect(subject.convert_args_to_string({foo: 'Foo'})).to eq('foo=Foo') }
    it { expect(subject.convert_args_to_string({foo: 'Foo', 'bar' => 'Bar'})).to eq('foo=Foo&bar=Bar') }
  end

  describe '#crafted_url_with' do
    let(:url) { 'url' }
    let(:func) { 'func' }
    let(:api_key) { '1234' }
    let(:args) { 'aaa=bbb&ccc=ddd' }
    subject { Shodan::Shodan.new(api_key) }
    it { expect(subject.crafted_url_with(url, func, api_key, args)).to eq("#{url}#{func}?key=#{api_key}&#{args}") }
  end
end