from canari.maltego.transform import Transform
from canari.maltego.entities import GPS, Port
from yetigo.transforms.entities import Ip, Hostname, Company, As
from yetigo.transforms.utils import run_oneshot, get_observable
from dateutil import parser


class Shodan(Transform):

    input_type = Ip
    display_name = '[YT] Shodan'

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot('Shodan', request, config)

        current_node = list(
            filter(lambda x: 'value' in x and x['value'] == entity.value,
                   res['nodes']))

        context_shodan = list(filter(lambda x: x['source'] == 'shodan_query',
                                     current_node[0]['context']))
        last_context_shodan = sorted(context_shodan,
                                     key=lambda x: parser.parse(
                                         x['last_update']))[0]

        for d in last_context_shodan['domains']:
            hostname = Hostname(d)
            hostname.link_label = 'last_update: %s' % last_context_shodan[
                'last_update']
            response += hostname

        for h in last_context_shodan['hostnames']:
            hostname = Hostname(h)
            hostname.link_label = 'last_update: %s' % last_context_shodan[
                'last_update']
            response += hostname

        if 'org' in last_context_shodan and last_context_shodan['org']:
            company = Company(last_context_shodan['org'])
            company.link_label = 'hoster'
            response += company

        asn = As(last_context_shodan['asn'].split('AS')[1])
        response += asn

        for p in last_context_shodan['ports']:
            port = Port(p)
            port.link_label = 'service'
            response += port
        return response