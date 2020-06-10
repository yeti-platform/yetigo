import sys

from canari.maltego.entities import Phrase, Domain
from canari.maltego.message import Entity, IntegerEntityField, StringEntityField \
    , MatchingRule, EnumEntityField, ArrayEntityField

__all__ = [
    'SourceYeti', 'Observable', 'Domain'
]


def str_to_class(classname):
    return getattr(sys.modules[__name__], classname)


class SourceYeti(Phrase):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    link = StringEntityField('link', display_name='link',
                             matching_rule=MatchingRule.Loose)


class Actor(Entity):

    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    actor = StringEntityField('Actor', display_name='Actor')
    tags = ArrayEntityField('Tags', display_name='Tags')


class Exploits(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Campaign(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    campaign = StringEntityField('Campaign', display_name='Campaign')
    tags = ArrayEntityField('Tags', display_name='Tags')


class Malware(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    malware = StringEntityField('Malware', display_name='Malware')
    tags = ArrayEntityField('Tags', display_name='Tags')


class Company(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'
    name = StringEntityField('Name', display_name='Name')
    tags = ArrayEntityField('Tags', display_name='Tags')


class Observable(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    observable = StringEntityField('Observable', display_name='Observable')
    type_obs = StringEntityField('type', display_name='type')
    tags = ArrayEntityField('Tags', display_name='Tags')
    context = StringEntityField('Context', display_name='Context')
    source = StringEntityField('Source', display_name='Source')


class Domain(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Hostname(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Hash(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Ip(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class File(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Url(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'
