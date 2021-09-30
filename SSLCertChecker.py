__author__ = "Fedorov Sergei"
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "Fedorov Sergei"
__email__ = "8ergo@mail.ru"
__status__ = "Production"

from requests.packages.urllib3.contrib import pyopenssl as reqs
import requests
import datetime

debug = False # Отвечает за вывод инфы для диагностики в консоль
enable_alerts_to_tg = True # Отвечает за отправку уведомлений в TG
bot_token = '' # Token бота
bot_chatID = '' # ID чата в который отправлять уведомления
path_to_host_file = './host_list.txt' # Путь к файлу списка доменных имен для проверки сертификатов
days_before_alert = 30 # За сколько дней начать уведомлять об окончании сертификата


def alert_to_tg(msg_text):
    '''Send message in TG'''
    response = requests.post(
        url=f"https://api.telegram.org/bot{bot_token}/sendMessage",
        data={'chat_id': bot_chatID, 'text': msg_text}
    )
    return response.json()


def check_cert(cert, host):
    '''Check date in cert and now'''
    current_date = datetime.datetime.now()
    expiration_date = datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"), '%Y%m%d%H%M%SZ')
    begin_date = datetime.datetime.strptime(cert.get_notBefore().decode("utf-8"), '%Y%m%d%H%M%SZ')
    betwin = expiration_date - current_date
    
    if debug:
        print(f"Date begin: {begin_date}")
        print(f"Date end: {expiration_date}")
        print(f"Days before end: {betwin}")

    if current_date < begin_date:
        return f"‼️ Внимание ‼️\n⚠️Для {host} срок действия SSL-сертификата еще не начался.\n📅Начало {str(begin_date)}."
    elif betwin.days <= days_before_alert:
        return f"‼️ Внимание ‼️\n⚠️Для {host} скоро закончится срок действия SSL-сертификата.\n📅Осталось {str(betwin.days)} дней."
    elif current_date >= expiration_date:
        return f"‼️ Внимание ‼️\n⚠️Для {host} {str(expiration_date)} закончился срок действия SSL-сертификата."
    else:
        return "ok"


def get_cert(host, port=443):
    '''Get cert for host'''
    try:
        cert = reqs.OpenSSL.crypto.load_certificate(reqs.OpenSSL.crypto.FILETYPE_PEM, reqs.ssl.get_server_certificate((host, port)))
        return cert
    except Exception as ex:
        print(ex)
        return None


with open(path_to_host_file, 'r', encoding='UTF-8') as host_file:
    for line in host_file.readlines():
        print('='*10)
        host_cert = None
        result = None
        host_port = line.rstrip('\n').split(':')
        host = host_port[0]

        if len(host_port) > 1:
            port = host_port[1]
        else:
            port = 443
       
        print(f"{host}:{port}")
        host_cert = get_cert(host, port)
        if host_cert == None:
            continue
        result = check_cert(host_cert, host)
        print(result)
        if result != 'ok' and enable_alerts_to_tg:
            response = alert_to_tg(result)
            if debug:
                print(response)
            if response['ok']==True:
                print('Уведомление отправлено в ТГ')
            else:
                print('Проблема с отправкой уведомления')