from canari.maltego.transform import Transform

from yetigo.transforms.entities import Hostname, str_to_class, Ip
from yetigo.transforms.utils import get_yeti_connection, run_oneshot, \
    get_obs, create_response


class DNSDB_PDNS(Transform):
    input_type = Hostname
    display_name = '[YT] DNSDB PDNS'

    def do_transform(self, request, response, config):
        return create_response(request, response, config, 'DNSDB Passive DNS',
                               'DNSDB Passive DNS')


class DNSDBReversePDNSHostname(Transform):
    input_type = Hostname
    display_name = '[YT] DNSDB PDNS Reverse'

    def do_transform(self, request, response, config):
        return create_response(request, response, config, 'Reverse Passive DNS',
                               'DNSDB Passive DNS')


class DNSDBReversePDNSIp(Transform):
    input_type = Ip
    display_name = '[YT] DNSDB PDNS Reverse'

    def do_transform(self, request, response, config):
        return create_response(request, response, config, 'Reverse Passive DNS',
                               'DNSDB Passive DNS')



