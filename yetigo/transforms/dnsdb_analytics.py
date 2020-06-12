from canari.maltego.transform import Transform

from yetigo.transforms.entities import Hostname, str_to_class
from yetigo.transforms.utils import get_yeti_connection, run_oneshot
from dateutil import parser


class DNSDB_PDNS(Transform):
    input_type = Hostname
    display_name ='[YT] DNSDB PDNS'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = run_oneshot(entity.value, 'DNSDB Passive DNS', yeti)
            if res:
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
                    history = sorted(list(filter(lambda x: 'DNSDB Passive DNS' in x['sources'],
                                            n['history'])),
                                     key=lambda x: parser.parser(x['last_seen']))

                    obs.link_label = '%s:%s' % (history[0]['description'],
                                                history[0]['last_seen'])
                    response += obs

                return response
