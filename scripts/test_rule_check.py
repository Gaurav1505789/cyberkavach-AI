from dataset.utils.url_normalize import normalize_url
from dataset.utils.url_rules import rule_check

info = normalize_url('http://varcode.in')
print('normalize:', info)
print('rule_check:', rule_check(info))
