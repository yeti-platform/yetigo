import json

from canari.maltego.transform import Transform

from yetigo.transforms.entities import Ip, Url, Hostname, Text
from yetigo.transforms.utils import run_oneshot


class UrlScanIoIP(Transform):
    input_type = Ip
    display_name = '[YT] UrlScanIO Ip'

    def do_transform(self, request, response, config):
        res = run_oneshot('UrlScanIo', request, config)
        if res:
            for n in res['nodes']:

                contexts_urlscan = list(filter(lambda x: x['source'] == 'UrlScanIo',
                                              n['context']))

                for context in contexts_urlscan:
                    results_json = json.loads(context['raw'])
                    for r in results_json:
                        page = r['page']
                        if 'url' in page:
                            url = Url(page['url'])
                            url.link_label = 'url'
                            response += url
                        if 'domain' in page:
                            hostname = Hostname(page['domain'])
                            hostname.link_label = 'domain'
                            response += hostname

                        if 'asn' in page:
                            asn = page['asn']
                            if 'AS' in asn:
                                as_ent = Text(asn.split('AS')[1])
                            else:
                                as_ent = Text(asn)
                            as_ent.link_label = 'AS'
                            response += as_ent
                        if 'server' in page:
                            server = Text(page['server'])
                            server.link_label = 'server'
                            response += server

                        task = r['task']

                        if 'url' in task:
                            url = Url(task['url'])
                            url.link_label = 'task url %s' % task['time']
                            response += url

                return response



