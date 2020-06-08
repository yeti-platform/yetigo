import json

from canari.maltego.transform import Transform
from dateutil.parser import parser

from yetigo.transforms.entities import Hash
from yetigo.transforms.utils import get_yeti_connection, get_av_sig, \
    get_hash_entities


class VTHashYeti(Transform):
    input_type = Hash
    display_name = '[YT] Hash Virustotal'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            observable = yeti.observable_add(entity.value)
            oneshot = yeti.get_analytic_oneshot('Virustotal')
            res = yeti.analytics_oneshot_run(oneshot, observable)
            if res:
                virus_res = res['nodes'][0]
                context_vt = list(
                    filter(lambda x: x['source'] == 'virustotal_query',
                           res['nodes'][0]['context']))
                context_filter = sorted(context_vt,
                                        key=lambda x: parser.parse(
                                            x['scan_date']))
                if len(context_filter) > 0:
                    last_context = context_filter[0]
                    vt_res = json.loads(last_context['raw'])
                    for h in get_hash_entities(vt_res,
                                               list_hash=['md5', 'sha256',
                                                          'sha1']):
                        if h.value != entity.value:
                            response += h

                    for ph in get_av_sig(vt_res['scans'].items()):
                        response += ph
            return response

