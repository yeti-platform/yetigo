from canari.maltego.entities import Hashtag, Phrase
from canari.maltego.message import Unknown, Bookmark, Field
from canari.maltego.transform import Transform
from yetigo.transforms.utils import get_yeti_connection, mapping_yeti_to_maltego
from dateutil import parser


from yetigo.transforms.entities import SourceYeti

class ObservableInYeti(Transform):
    input_type = Unknown
    display_name = "In Yeti?"

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = yeti.observable_search(value=entity.value)
            response += mapping_yeti_to_maltego[res[0]['type']](entity.value,
                                                                bookmark=Bookmark.Green)
            return response


class TagsInYeti(Transform):
    input_type = Unknown
    display_name = 'Tags In Yeti'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = yeti.observable_search(value=entity.value)
            if res:
                response += mapping_yeti_to_maltego[res[0]['type']](
                    entity.value,
                    bookmark=Bookmark.Green)
                for t in res[0]['tags']:
                    response += Hashtag(t['name'],
                                        link_label='last_seen: %s' % t[
                                            'last_seen'],
                                        bookmark=Bookmark.Green)
            return response


class SourcesInYeti(Transform):
    input_type = Unknown
    display_name = 'Sources In Yeti'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = yeti.observable_search(value=entity.value)
            if res:
                response += mapping_yeti_to_maltego[res[0]['type']](
                    entity.value,
                    bookmark=Bookmark.Green)
                ph = Phrase('Yeti')
                ph += Field('link', res[0]['human_url'], display_name='link')
                response += ph
                for t in res[0]['context']:
                    ph = Phrase(t['source'])
                    if 'link' in t:
                        ph += Field('link', t['link'], display_name='link')
                    response += ph

            return response


class TagToObservables(Transform):
    input_type = Unknown
    display_name = 'Tags to observables'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = yeti.observable_search(tags=entity.value)
            for item in res:
                if item['type'] == 'File':
                    value = entity.value.split(':')[1]

                else:
                    value = item['value']

                entity_add = mapping_yeti_to_maltego[item['type']](
                    value)
                created_date = parser.parse(item['created'])
                entity_add.link_label = 'created:%s' % created_date.isoformat()
                response += entity_add

        return response