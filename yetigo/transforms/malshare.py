from canari.maltego.transform import Transform

from yetigo.transforms.entities import Hash
from yetigo.transforms.utils import create_response


class Malshare(Transform):
    input_type = Hash
    display_name = '[YT] Malshare'

    def do_transform(self, request, response, config):
        return create_response(request, response, config, 'MalShare',
                               'malshare_query')
