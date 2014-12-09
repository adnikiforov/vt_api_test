# spec/spec_helper.rb
require 'webmock/rspec'
WebMock.disable_net_connect!(allow_localhost: true)

RSpec.configure do |config|
  config.before(:each) do
    body = <<-BODY
      {
  \"permalink\": \"https://www.virustotal.com/url/adce8cf3fee600cbc92e519824cae16cc3c195d6cd0a4dd5ccc631193cf706e3/analysis/1417961468/\",
  \"resource\": \"sitesecure.ru\",
  \"url\": \"http://sitesecure.ru/\",
  \"response_code\": 1,
  \"scan_date\": \"2014-12-07 14:11:08\",
  \"scan_id\": \"adce8cf3fee600cbc92e519824cae16cc3c195d6cd0a4dd5ccc631193cf706e3-1417961468\",
  \"verbose_msg\": \"Scan finished, scan information embedded in this object\",
  \"filescan_id\": null,
  \"positives\": 0,
  \"total\": 61,
  \"scans\": {
    \"CLEAN MX\": {
      \"detected\": false,
      \"result\": \"malware site\"
    },
    \"MalwarePatrol\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"ZDB Zeus\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Tencent\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"AutoShun\": {
      \"detected\": false,
      \"result\": \"unrated site\"
    },
    \"ZCloudsec\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"PhishLabs\": {
      \"detected\": false,
      \"result\": \"unrated site\"
    },
    \"K7AntiVirus\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Quttera\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Spam404\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"AegisLab WebGuard\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"MalwareDomainList\": {
      \"detected\": false,
      \"result\": \"clean site\",
      \"detail\": \"http://www.malwaredomainlist.com/mdl.php?search=sitesecure.ru\"
    },
    \"ZeusTracker\": {
      \"detected\": false,
      \"result\": \"clean site\",
      \"detail\": \"https://zeustracker.abuse.ch/monitor.php?host=sitesecure.ru\"
    },
    \"zvelo\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Google Safebrowsing\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Kaspersky\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"BitDefender\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Dr.Web\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"ADMINUSLabs\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"C-SIRT\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"CyberCrime\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Websense ThreatSeeker\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"VX Vault\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Webutation\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Trustwave\": {
      \"detected\": false,
      \"result\": \"unrated site\"
    },
    \"Web Security Guard\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"G-Data\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Malwarebytes hpHosts\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Wepawet\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"AlienVault\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Emsisoft\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Malc0de Database\": {
      \"detected\": false,
      \"result\": \"clean site\",
      \"detail\": \"http://malc0de.com/database/index.php?search=sitesecure.ru\"
    },
    \"SpyEyeTracker\": {
      \"detected\": false,
      \"result\": \"clean site\",
      \"detail\": \"https://spyeyetracker.abuse.ch/monitor.php?host=sitesecure.ru\"
    },
    \"malwares.com URL checker\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Phishtank\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Malwared\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Avira\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"OpenPhish\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Antiy-AVL\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"SCUMWARE.org\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"FraudSense\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Opera\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Comodo Site Inspector\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Malekal\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"ESET\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Sophos\": {
      \"detected\": false,
      \"result\": \"unrated site\"
    },
    \"Yandex Safebrowsing\": {
      \"detected\": false,
      \"result\": \"clean site\",
      \"detail\": \"http://yandex.com/infected?l10n=en&url=http://sitesecure.ru/\"
    },
    \"SecureBrain\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Malware Domain Blocklist\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Blueliv\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Netcraft\": {
      \"detected\": false,
      \"result\": \"unrated site\"
    },
    \"PalevoTracker\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"CRDF\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"ThreatHive\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"ParetoLogic\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Rising\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"URLQuery\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"StopBadware\": {
      \"detected\": false,
      \"result\": \"unrated site\"
    },
    \"Sucuri SiteCheck\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Fortinet\": {
      \"detected\": false,
      \"result\": \"clean site\"
    },
    \"Baidu-International\": {
      \"detected\": false,
      \"result\": \"clean site\"
    }
  }
}
    BODY

    stub_request(:post, "http://www.virustotal.com/vtapi/v2/url/report").
        with(:body => {"apikey" => "fb28dcb16dcdc52c7776b3d703779e16b351c8e798392d5984dc4027b60e2230", "resource" => "sitesecure.ru"},
             :headers => {'Accept' => '*/*; q=0.5, application/xml', 'Accept-Encoding' => 'gzip, deflate', 'Content-Length' => '94', 'Content-Type' => 'application/x-www-form-urlencoded', 'User-Agent' => 'Ruby'}).
        to_return(:status => 200, :body => body, :headers => {})
  end
end
