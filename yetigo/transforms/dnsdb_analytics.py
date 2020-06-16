from canari.maltego.transform import Transform

from yetigo.transforms.entities import Hostname, str_to_class, Ip
from yetigo.transforms.utils import get_yeti_connection, run_oneshot, \
    get_obs_dnsdb


class DNSDB_PDNS(Transform):
    input_type = Hostname
    display_name = '[YT] DNSDB PDNS'

    def do_transform(self, request, response, config):
        return create_response(request, response, config, 'DNSDB Passive DNS')


class DNSDBReversePDNSHostname(Transform):
    input_type = Hostname
    display_name = '[YT] DNSDB PDNS Reverse'

    def do_transform(self, request, response, config):
        return create_response(request, response, config, 'Reverse Passive DNS')


class DNSDBReversePDNSIp(Transform):
    input_type = Ip
    display_name = '[YT] DNSDB PDNS Reverse'

    def do_transform(self, request, response, config):
        return create_response(request, response, config, 'Reverse Passive DNS')


def create_response(request, response, config, name_analytic):
    entity = request.entity
    yeti = get_yeti_connection(config)

    if yeti:
        res = run_oneshot(entity.value, name_analytic, yeti)
        if res:
            for obs in get_obs_dnsdb(res, entity):
                response += obs
            return response
