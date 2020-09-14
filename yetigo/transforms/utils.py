from canari.maltego.entities import Domain, Hash, IPv4Address, URL, Phrase
from canari.maltego.message import MaltegoException
from yetigo.transforms.entities import Hostname, Ip, str_to_class

from dateutil import parser
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


def run_oneshot(name_oneshost, request, config):
    entity = request.entity
    yeti = get_yeti_connection(config)
    observable = yeti.observable_add(entity.value)
    oneshot = yeti.get_analytic_oneshot(name_oneshost)
    res = yeti.analytics_oneshot_run(oneshot, observable)
    if res:
        return res


def get_obs(res, entity, source):
    current_node = list(filter(lambda x: x['value'] == entity.value,
                               res['nodes']))[0]
    nodes = list(filter(lambda x: x['value'] != entity.value,
                        res['nodes']))
    links = res['links']

    nodes = {n['_id']: n for n in nodes}

    selected_nodes = {_id:
                          list(filter(
                              lambda x: x['src']['id'] == _id or
                                        x['dst']['id'] == _id,
                              links))[0] for _id in nodes.keys()}

    for _id, n in selected_nodes.items():
        type_obs = nodes[_id]['_cls'].split('.')[1]
        obs = str_to_class(type_obs)(nodes[_id]['value'])
        history = sorted(
            list(filter(lambda x: source in x['sources'],
                        n['history'])),
            key=lambda x: parser.parser(x['last_seen']))

        obs.link_label = '%s:%s' % (history[0]['description'],
                                    history[0]['last_seen'])

        yield obs


def get_observable(obs_id, config):
    yeti = get_yeti_connection(config)
    obs = yeti.observable_details(obs_id)
    if obs:
        return obs


def create_response(request, response, config, name_analytic, source):
    res = run_oneshot('Virustotal', request, config)
    if res:
        for obs in get_obs(res, request.entity, source):
            response += obs
        return response


def get_entity_for_observable(request, response, config, name_entity=None):
    entity = request.entity
    yeti = get_yeti_connection(config)

    if yeti:
        obj = yeti.observable_search(value=entity.value)[0]
        res = select_request_observable_to_entity(yeti, name_entity, obj)
        if res and 'objs' in res:
            for item in res['objs']:
                entity_name = item['type']
                entity_add = None
                try:
                    entity_add = str_to_class(entity_name)()
                except:
                    print('failed')
                    pass
                if entity_add:
                    if 'tags' in item:
                        entity_add.tags = [t for t in item['tags']]
                    entity_add.value = item['name']
                    response += entity_add
        return response


def get_entity_to_entity(request, response, config, name_entity=None):
    entity = request.entity
    yeti = get_yeti_connection(config)

    if yeti:

        ent = yeti.entity_search(name=entity.value)[0]
        res = select_request_entity_to_entity(yeti, name_entity, ent)
        if res and 'objs' in res:
            for item in res['objs']:
                entity_add = str_to_class(item['type'])()
                entity_add.tags = item['tags']
                entity_add.value = item['name']

                response += entity_add
        return response


def select_request_observable_to_entity(yeti, name_entity, obj):
    if name_entity == 'company':
        return yeti.observable_to_company(obj['id'])
    elif name_entity == 'actor':
        return yeti.observable_to_actor(obj['id'])
    elif name_entity == 'campaign':
        return yeti.observable_to_campaign(obj['id'])
    elif name_entity == 'exploitkit':
        return yeti.observable_to_exploitkit(obj['id'])
    elif name_entity == 'exploit':
        return yeti.observable_to_exploit(obj['id'])
    elif name_entity == 'indicator':
        return yeti.observable_to_indicator(obj['id'])
    elif name_entity == 'malware':
        return yeti.observable_to_malware(obj['id'])
    else:
        return None


def select_request_entity_to_entity(yeti, name_entity, entity):
    if name_entity == 'company':
        return yeti.entity_to_company(entity['id'])
    elif name_entity == 'actor':
        return yeti.entity_to_actor(entity['id'])
    elif name_entity == 'campaign':
        return yeti.entity_to_campaign(entity['id'])
    elif name_entity == 'exploitkit':
        return yeti.entity_to_exploitkit(entity['id'])
    elif name_entity == 'exploit':
        return yeti.entity_to_exploit(entity['id'])
    elif name_entity == 'indicator':
        return yeti.entity_to_indicator(entity['id'])
    elif name_entity == 'malware':
        return yeti.entity_to_malware(entity['id'])
    else:
        return None


def do_pdns(res, entity, response):
    if res:
        for item in res['nodes']:
            if item['value'] != entity.value:
                entity_add = str_to_class(item['_cls'].split('.')[1])(
                    item['value'])
                entity_add.link_label = 'Metadata'
                response += entity_add

    return response


def do_pdns_pt(res, entity, response):
    for item in res['nodes']:
        if item['value'] != entity.value:
            link = list(filter(
                lambda x: x['dst']['id'] == item['_id'] or x['src']['id'] ==
                          item['_id'], res['links']))[0]

            entity_add = Ip(item['value'])
            entity_add.link_label = 'first_seen: %s last_seen: %s' % (
                link['first_seen'], link['last_seen'])
            response += entity_add
    return response


def do_get_malware_pt(res, entity, response):
    for item in res['nodes']:
        if item['value'] != entity.value:
            entity_add = Hash(item['value'])
            entity_add.link_label = 'Malware PT'
            response += entity_add
    return response