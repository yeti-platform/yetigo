import json
import logging

from canari.maltego.entities import Hashtag, Phrase
from canari.maltego.message import Unknown, Bookmark, Field
from canari.maltego.transform import Transform
from yetigo.transforms.utils import get_yeti_connection, \
    mapping_yeti_to_maltego, get_hash_entities, get_av_sig, do_transform, \
    get_entity_for_observable, get_entity_to_entity
from yetigo.transforms.entities import str_to_class, Observable, Domain, Hash, \
    YetiEntity, Tag, SourceYeti
from dateutil import parser
import validators
from yetigo.transforms.entities import SourceYeti


class ObservableInYeti(Transform):
    input_type = Observable
    display_name = "[YT] In Yeti?"

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = yeti.observable_search(value=entity.value)
            response += mapping_yeti_to_maltego[res[0]['type']](entity.value,
                                                                bookmark=Bookmark.Green)
            return response


class TagsInYeti(Transform):
    input_type = Observable
    display_name = '[YT] Tags In Yeti'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = yeti.observable_search(value=entity.value)
            if res:
                for t in res[0]['tags']:
                    response += Tag(t['name'],
                                        link_label='last_seen: %s' % t[
                                            'last_seen'],
                                        bookmark=Bookmark.Green)
            return response


class SourcesInYeti(Transform):
    input_type = Observable
    display_name = '[YT] Sources In Yeti'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            res = yeti.observable_search(value=entity.value)
            if res:
                src = SourceYeti('Yeti')
                src.link = 'link'
                response += src
                for t in res[0]['context']:
                    ph = SourceYeti(t['source'])
                    if 'link' in t:
                        ph += Field('link', t['link'], display_name='link')
                    response += ph

            return response


class TagToObservables(Transform):
    input_type = Observable
    display_name = '[YT] Tags to observables'

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


class NeighborsObservable(Transform):
    input_type = Observable
    display_name = '[YT] Observable to observables'

    def do_transform(self, request, response, config):
        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            obs = yeti.observable_search(value=entity.value)
            if obs:
                res = yeti.neighbors_observables(obs[0]['id'])
                if res and 'objs' in res:
                    for item in res['objs']:
                        type_obs = item['type']
                        entity_add = None
                        try:
                            entity_add = str_to_class(type_obs)(
                                item['value'])
                        except AttributeError as e:
                            pass

                        if entity_add:
                            entity_add.link_label = ' '.join(
                                [s for s in item['sources']])
                            if type_obs == 'Url':
                                entity_add.url = item['value']
                            entity_add.Type = type_obs
                            created_date = parser.parse(item['created'])
                            if created_date:
                                entity_add.link_label = ' created:%s' % created_date.isoformat()
                            response += entity_add

            return response


class ObservableToCompany(Transform):
    input_type = Observable
    display_name = '[YT] Observable to Company'

    def do_transform(self, request, response, config):
        return get_entity_for_observable(request, response, config,
                                         name_entity='company')


class ObservableToCampaign(Transform):
    input_type = Observable
    display_name = '[YT] Observable to Campaign'

    def do_transform(self, request, response, config):
        return get_entity_for_observable(request, response, config,
                                         name_entity='campaign')


class ObservableToIndicator(Transform):
    input_type = Observable
    display_name = '[YT] Observable to Indicator'

    def do_transform(self, request, response, config):
        return get_entity_for_observable(request, response, config,
                                         name_entity='indicator')


class ObservableToMalware(Transform):
    input_type = Observable
    display_name = '[YT] Observable to Malware'

    def do_transform(self, request, response, config):
        return get_entity_for_observable(request, response, config,
                                         name_entity='malware')


class ObservableToActor(Transform):
    input_type = Observable
    display_name = '[YT] Observable to Actor'

    def do_transform(self, request, response, config):
        return get_entity_for_observable(request, response, config,
                                         name_entity='actor')


class ObservableToExploit(Transform):
    input_type = Observable
    display_name = '[YT] Observable to Exploit'

    def do_transform(self, request, response, config):
        return get_entity_for_observable(request, response, config,
                                         name_entity='exploit')


class ObservableToExploitKit(Transform):
    input_type = Observable
    display_name = '[YT] Observable to Exploit Kit'

    def do_transform(self, request, response, config):
        return get_entity_for_observable(request, response, config,
                                         name_entity='exploitkit')


class EntityToCompany(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to Company'

    def do_transform(self, request, response, config):
        return get_entity_to_entity(request, response, config,
                                    name_entity='company')


class EntityToCampaign(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to Campaign'

    def do_transform(self, request, response, config):
        return get_entity_to_entity(request, response, config,
                                    name_entity='campaign')


class EntityToIndicator(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to Indicator'

    def do_transform(self, request, response, config):
        return get_entity_to_entity(request, response, config,
                                    name_entity='indicator')


class EntityToMalware(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to Malware'

    def do_transform(self, request, response, config):
        return get_entity_to_entity(request, response, config,
                                    name_entity='malware')


class EntityToActor(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to Actor'

    def do_transform(self, request, response, config):
        return get_entity_to_entity(request, response, config,
                                    name_entity='actor')


class EntityToExploit(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to Exploit'

    def do_transform(self, request, response, config):
        return get_entity_to_entity(request, response, config,
                                    name_entity='exploit')


class EntityToExploitKit(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to Exploit Kit'

    def do_transform(self, request, response, config):
        return get_entity_to_entity(request, response, config,
                                    name_entity='exploitkit')


class EntityToObservables(Transform):
    input_type = YetiEntity
    display_name = '[YT] Entity to observables'

    def do_transform(self, request, response, config):

        entity = request.entity
        yeti = get_yeti_connection(config)

        if yeti:
            ent = yeti.entity_search(name=entity.value)[0]
            res = yeti.entity_to_observables(ent['id'])
            if res and 'objs' in res:
                for item in res['objs']:
                    type_obs = item['type']
                    entity_add = str_to_class(type_obs)(item['value'])
                    entity_add.tags = [t['name'] for t in item['tags']]
                    response += entity_add
        return response


class AddDomain(Transform):
    input_type = Domain
    display_name = '[YT] Add Domain'

    def do_transform(self, request, response, config):
        return do_transform(request, response, config)
