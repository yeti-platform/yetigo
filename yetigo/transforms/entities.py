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

class YetiEntity(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    name = StringEntityField('name', display_name='name')
    tags = ArrayEntityField('tags', display_name='tags')

class Actor(YetiEntity):

    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

class Exploits(YetiEntity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Campaign(YetiEntity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Malware(YetiEntity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Company(YetiEntity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'



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
    malicious = StringEntityField('Malicious', display_name='Malicious')
    undetected = StringEntityField('Undetected', display_name='Undetected')
    suspicious = StringEntityField('Suspicious', display_name='Suspicious')
    magic = StringEntityField('Magic', display_name='Magic')


class Ip(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class File(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Url(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Text(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

class As(Observable):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'