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