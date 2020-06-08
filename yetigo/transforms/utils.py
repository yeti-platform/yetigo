from canari.maltego.entities import Domain, Hash, IPv4Address, URL, Phrase
from canari.maltego.message import MaltegoException
import pyeti
import validators

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


def get_hash_entities(context, list_hash):
    for type_h in list_hash:
        h = Hash(value=context[type_h])
        h.type = type_h
        h.link_label = type_h
        yield h

def get_av_sig(signature_vt):

    for av, res in signature_vt:
        if res['detected']:
            ph = Phrase(value=res['result'])
            ph.link_label = 'update:%s av:%s' % (res['update'],
                                                 av)

            yield ph


def do_transform(request, response, config):
    entity = request.entity
    yeti = get_yeti_connection(config)
    if yeti:
        tags = entity.tags
        value = entity.value
        type_obs = entity.type

        context = {}
        if validators.url(entity.context):
            context['url'] = entity.context
            context['source'] = entity.source

        res = yeti.observable_add(value, tags, context=context,
                                  source='Maltego')
        if res:
            return response