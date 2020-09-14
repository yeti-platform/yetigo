from canari.maltego.transform import Transform

from yetigo.transforms.entities import Hostname, Ip
from yetigo.transforms.utils import run_oneshot,do_pdns_pt


class PTPassiveDNSByDomain(Transform):

    input_type = Hostname
    display_name = '[YT] PT Passive DNS by Domain'

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot('PassiveTotal Passive DNS', request, config)
        return do_pdns_pt(res, entity, response)


class PTPassiveDNSByIP(Transform):

    input_type = Hostname
    display_name = '[YT] PT Passive DNS by IP'

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot('PassiveTotal Passive DNS', request, config)
        return do_pdns_pt(res, entity, response)