from canari.maltego.entities import Domain, Hash, IPv4Address, URL, Phrase
from canari.maltego.message import MaltegoException
import pyeti
import validators

from yetigo.transforms.entities import Hostname, Ip

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


def get_status_domains(vt_result):
    if 'scans' in vt_result:
        for av, res in vt_result['scans'].items():
            ph = Phrase(value=av)
            ph.link_label = res['result']

            yield ph


def get_sample_by_ip_vt(current_context, keys):
    for k in keys:
        if k in current_context:
            for samp in current_context[k]:
                h = Hash(samp['sha256'])
                h.link_label = 'scoring: %s date: %s' % (
                samp['positives'] / samp['total'], samp['date'])
                yield h


def get_hostnames_by_ip_vt(current_context):

    for r in current_context['resolutions']:
        h = Hostname(r['hostname'])
        h.link_label = 'last resolved: %s' % r['last_resolved']
        yield h


def get_ips_by_hostname_vt(current_context):
    for r in current_context:
        ip = Ip(r['ip_address'])
        ip.link_label = '%s:%s' % ('Passive DNS', r['last_resolved'])
        yield ip


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
