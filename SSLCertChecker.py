__author__ = "Fedorov Sergei"
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "Fedorov Sergei"
__email__ = "8ergo@mail.ru"
__status__ = "Production"

import datetime
from requests.packages.urllib3.contrib import pyopenssl as reqs
import requests


DEBUG = False # Отвечает за вывод инфы для диагностики в консоль
ENABLE_ALERTS_TO_TG = True # Отвечает за отправку уведомлений в TG
BOT_TOKEN = '' # Token бота
BOT_CHAT_ID = '' # ID чата в который отправлять уведомления
PATH_TO_HOST_FILE = './host_list.txt' # Путь к файлу списка доменных имен для проверки сертификатов
DAYS_BEFORE_ALERT = 30 # За сколько дней начать уведомлять об окончании сертификата


def alert_to_tg(msg_text):
    '''Send message in TG'''
    tg_result = requests.post(
        url=f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data={'chat_id': BOT_CHAT_ID, 'text': msg_text}
    )
    return tg_result.json()


def check_cert(cert, host_for_check):
    '''Check date in cert and now'''
    check_result = None
    current_date = datetime.datetime.now()
    expiration_date = datetime.datetime.strptime(
        cert.get_notAfter().decode("utf-8"),
        '%Y%m%d%H%M%SZ'
        )
    begin_date = datetime.datetime.strptime(
        cert.get_notBefore().decode("utf-8"),
        '%Y%m%d%H%M%SZ'
        )
    betwin = expiration_date - current_date
    if DEBUG:
        print(f"Date begin: {begin_date}")
        print(f"Date end: {expiration_date}")
        print(f"Days before end: {betwin}")
    if current_date < begin_date:
        check_result = f"‼️ Внимание ‼️\n⚠️Для {host_for_check} срок действия SSL-сертификата еще не начался.\n📅Начало {str(begin_date)}."
    elif betwin.days <= DAYS_BEFORE_ALERT:
        check_result = f"‼️ Внимание ‼️\n⚠️Для {host_for_check} скоро закончится срок действия SSL-сертификата.\n📅Осталось {str(betwin.days)} дней."
    elif current_date >= expiration_date:
        check_result = f"‼️ Внимание ‼️\n⚠️Для {host_for_check} {str(expiration_date)} закончился срок действия SSL-сертификата."
    else:
        check_result = "ok"
    return check_result


def get_cert(host_for_check, port_for_check=443):
    '''Get cert for host'''
    try:
        cert = reqs.OpenSSL.crypto.load_certificate(
            reqs.OpenSSL.crypto.FILETYPE_PEM,
            reqs.ssl.get_server_certificate((host_for_check, port_for_check))
            )
        return cert
    except Exception as ex:
        print(ex)
        return None


with open(PATH_TO_HOST_FILE, 'r', encoding='UTF-8') as host_file:
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
        if host_cert is None:
            continue
        result = check_cert(host_cert, host)
        print(result)
        if result != 'ok' and ENABLE_ALERTS_TO_TG:
            response = alert_to_tg(result)
            if DEBUG:
                print(response)
            if response['ok']:
                print('Уведомление отправлено в ТГ')
            else:
                print('Проблема с отправкой уведомления')
