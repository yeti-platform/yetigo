from canari.maltego.entities import Domain, Hash, IPv4Address, URL
from canari.maltego.message import MaltegoException
import pyeti

yeti_connection = None

mapping_yeti_to_maltego = {

    "Hostname": Domain,
    "Hash": Hash,
    "Ip": IPv4Address,
    "Url": URL,
    "File": Hash,
    "Domain": Domain

}


def get_yeti_connection(config=None):

    global yeti_connection

    if yeti_connection:
        return yeti_connection

    if not config:
        raise MaltegoException("Configuration is empty !")

    assert 'Yeti.local.api_url' in config and 'Yeti.local.api_key' in config

    try:
        api = pyeti.YetiApi(url=config['Yeti.local.api_url'],
                            api_key=config['Yeti.local.api_key'])
        return api
    except Exception:
        raise MaltegoException("Yeti Error")