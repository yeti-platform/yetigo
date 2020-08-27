from canari.maltego.transform import Transform

from yetigo.transforms.entities import Hash
from yetigo.transforms.utils import run_oneshot,str_to_class


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
