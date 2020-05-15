from canari.maltego.entities import Phrase
from canari.maltego.message import Entity, IntegerEntityField, StringEntityField, MatchingRule

__all__ = [
    'SourceYeti'
]


class SourceYeti(Phrase):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    link = StringEntityField('link', display_name='link',
                             matching_rule=MatchingRule.Loose)

class Actor(Entity):

    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    actor = StringEntityField('Actor', display_name='Actor')


class Exploits(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'


class Campaign(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    campaign = StringEntityField('Campaign', display_name='Campaign')


class Malware(Entity):
    _category_ = 'Yeti'
    _namespace_ = 'Yetigo'

    malware = StringEntityField('Malware', display_name='Malware')

