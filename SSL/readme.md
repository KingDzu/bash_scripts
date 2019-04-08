# Назначение скрипта:
Автоматизация получения сертификата из Active Directory Certification Services для linux-стендов.
Удобен для тестовых стендов разработки, находящихся внутри доменной сети.

### Автор:
bgstack15@gmail.com

### Файлы:  
  
certreq.sh - основной скрипт, возможные параметры указанны в функции usage  
framework.sh - фраймворк для основного скрипта  
certreq.conf - конфиг для запуска  
  
### Структура конфига:  
  
CERTREQ_USER="" #имя пользователя имеющего доступ в MCAS  
CERTREQ_PASS="" # пароль пользователя  
CERTREQ_WORKDIR="$( mktemp -d )" # генерируемая рабочая папка в /tmp/  
CERTREQ_TEMPLATE="Web Server" # шаблон запроса MCAS  
CERTREQ_CNLONG="hostname" # CN сертификата, требууется поставить нужный, в файле example данный параметр береться из hostname сервера  
CERTREQ_DNSSANS="hostname" # altDNSname сертификата  
CERTREQ_CNSHORT="$( echo "${CERTREQ_CNLONG%%.*}" )"  
CERTREQ_SUBJECT="/C=/S=/L=/O=/OU=/CN=${CERTREQ_CNPARAM:-CERTREQ_CNPARAM}"  
CERTREQ_CA=" " # хост MCAS  
  
### Запуск скрипта:  
  
* Копируем отредактированный под свои параметры certreq.conf в папку /tmp/  
* Запускаем certreq.sh  
* Забираем готовой сертификат с ключем из временной папки /tmp/t.XXXXXXX/  

