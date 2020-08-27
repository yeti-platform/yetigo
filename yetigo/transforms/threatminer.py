from canari.maltego.transform import Transform

from yetigo.transforms.entities import Hash, Hostname, Ip
from yetigo.transforms.utils import run_oneshot, str_to_class, do_pdns


class ThreatMinerRelativeHost(Transform):

    input_type = Hash
    display_name = '[YT] ThreatMiner - Related Hosts'

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot('Related Hosts', request, config)

        for item in res['nodes']:
            if item['value'] != entity.value:
                entity_add = str_to_class(item['_cls'].split('.')[1])(
                    item['value'])
                entity_add.link_label = 'Related Host'
                response += entity_add

        return response


class ThreatMinerRetrieveMetadata(Transform):
    input_type = Hash
    display_name = '[YT] ThreatMiner - Metadata'

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot('Retrieve metadata.', request, config)


class ThreatMinerPDNSHostname(Transform):
    input_type = Hostname
    display_name = '[YT] ThreatMiner - PDNS'

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot('ThreatMiner PDNS', request, config)

        return do_pdns(res, entity, response)


class ThreatMinerPDNSIP(Transform):
    input_type = Ip
    display_name = '[YT] ThreatMiner - PDNS'

    def do_transform(self, request, response, config):
        entity = request.entity
        res = run_oneshot('ThreatMiner PDNS', request, config)

        return do_pdns(res, entity, response)







