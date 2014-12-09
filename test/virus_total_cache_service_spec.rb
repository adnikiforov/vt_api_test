require 'rspec'
require './spec_helper'
require './virus_total_cache_service'

describe 'VirusTotalCacheService.scan' do
  before do
    @service = VirusTotalCacheService.new
    @url = 'sitesecure.ru'
  end

  it 'must return result' do
    response = @service.scan(@url)
    expect(response[:domain]).eql?(@url)
    expect(response[:safe]).eql?(false)
    expect(response[:scanners].count).eql?(61)
    expect(response[:problems]).to include({'CLEAN MX' => 'malware site'})
    expect(response[:trust]).to include({"Tencent" => "clean site", "Spam404" => "clean site", "Kaspersky" => "clean site", "BitDefender" => "clean site", "Dr.Web" => "clean site", "G-Data" => "clean site", "Avira" => "clean site", "ESET" => "clean site", "Sophos" => "unrated site", "Yandex Safebrowsing" => "clean site", "Fortinet" => "clean site"})
  end

end
