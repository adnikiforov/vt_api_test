require 'json'
require 'rest-client'

class VirusTotalCacheService
  # Хочу кое-что пояснить
  # К внешнему API можно относиться с доверием, а можно без доверия
  # Тут - первый случай: я верю, что API всегда вернет мне то, что обещает
  # Иначе можно надолго застрять с валидацией JSON Schema

  # Я задаю константы прямо в классе, но при желании их можно хранить где угодно
  ApiUrl = 'http://www.virustotal.com/vtapi/v2/url/report'
  ApiKey = 'fb28dcb16dcdc52c7776b3d703779e16b351c8e798392d5984dc4027b60e2230'
  ScannersList = ['Avira',
                  'BitDefender',
                  'Dr.Web',
                  'ESET',
                  'Fortinet',
                  'G-Data',
                  'Kaspersky',
                  'Sophos',
                  'Spam404',
                  'Tencent',
                  'Yandex Safebrowsing']

  # Здесь я считаю, что список проблемных результатов приходит нам сразу в downcase
  # Если это не так, то я приведу его к такому виду, чтобы избежать плясок с string case-insensitive comparsion
  # Хотя это возможно например так (и это быстрее Regexp и downarray на каждый поиск)
  # ProblemResultsList.any? { |s| s.casecmp(string) == 0 }
  ProblemResultsList = ['malware site',
                        'malicious site',
                        'phishing site']

  # На самом деле тут нет никакой инициализации, метод можно сделать статическим
  def scan(url)
    res = RestClient.post(ApiUrl, :apikey => ApiKey, :resource => url)
    case res.response_code
      when 200
        generate_result(json)
      when 204
        logger.error 'VirusTotal API request rate limit quota exceeds'
      else
        logger.error 'Some error here'
    end
  end

  private
  def generate_result(json)
    # В случае, если искомого не найдено - лучше вернуть пустой объект
    # И дальше не разбирать
    return {} if json['response_code'] != 1

    # Тут мы сворачиваем изначальное
    # {"ScannerName" => {"detected" => false, "result" => "clean site"}
    # к виду {"ScannerName" => "clean site"}
    scans = json['scans'].inject({}) { |h, (k, v)| h[k] = v['result']; h }

    safe = true
    problems = {}
    trusted = {}

    # Лучше сделать один обход и вытащить все результаты сразу
    # На самом деле даже свертку можно уместить сюда при необходимости
    scans.each do |key, scan|
      if ProblemResultsList.include?(scan['result'])
        safe = false
        problems[key] = scan
      end
      trusted[key] = scan if ScannersList.include?(key)
    end

    # И собираем все вместе
    # Теоретически можно было бы сделать всю сборку через Hash#select
    # Но получится громоздко, а выигрыш невелик
    {
        :domain => json['resource'],
        :scanners => scans,
        :safe => safe,
        :problems => problems,
        :trust => trusted
    }
  end

end
