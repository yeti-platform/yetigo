import json

from canari.maltego.transform import Transform
from dateutil import parser

from yetigo.transforms.entities import Hash, Domain, Ip, Hostname
from yetigo.transforms.utils import get_yeti_connection, get_av_sig, \
    get_hash_entities, get_status_domains,get_sample_by_ip_vt,get_hostnames_by_ip_vt,\
    get_ips_by_hostname_vt


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

class VTDomains(Transform):

    input_type = Hostname
    display_name = '[YT] VT Domain Status'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            oneshot = yeti.get_analytic_oneshot('Virustotal')
            observable = yeti.observable_add(entity.value)
            res = yeti.analytics_oneshot_run(oneshot, observable)
            if res:
                virus_res = res['nodes'][0]
                context_vt = list(
                    filter(lambda x: x['source'] == 'virustotal_query',
                           virus_res['context']))
                for c_vt in context_vt:
                    current_context = json.loads(c_vt['raw'])

                    for ph in get_status_domains(current_context):
                            response += ph
                    if 'resolutions' in current_context:
                        for ip in get_ips_by_hostname_vt(current_context):
                            response += ip
            return response

class VTIPStatus(Transform):

    input_type = Ip
    display_name = '[YT] VT IP Status'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti=get_yeti_connection(config)

        if yeti:
            oneshot = yeti.get_analytic_oneshot('Virustotal')
            observable = yeti.observable_add(entity.value)
            res = yeti.analytics_oneshot_run(oneshot, observable)

            if res:
                virus_res = res['nodes'][0]
                context_vt = list(
                    filter(lambda x: x['source'] == 'virustotal_query',
                           virus_res['context']))

                for c_vt in context_vt:
                    current_context = json.loads(c_vt['raw'])
                    for h in get_sample_by_ip_vt( current_context,
                                                 ['detected_communicating_samples',
                                                  'detected_downloaded_samples',
                                                  'detected_referrer_samples',
                                                  'undetected_communicating_samples',
                                                  'undetected_downloaded_samples',
                                                  'undetected_referrer_samples']
                                                 ):
                        response += h
                    if 'resolutions' in current_context:
                        for hostname in get_hostnames_by_ip_vt(current_context):
                            response += hostname
                return response






