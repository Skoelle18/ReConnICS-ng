import json

data_path = '../assets/cisa-csaf-ot-feed-tlp-white.json'

fp = open(data_path, 'r', encoding='utf-8')
data_json = fp.read()


data = json.loads(data_json)

print(list(data['feed'].keys()))

ttv = list(data['feed']['entry'])

# 33957 length
print(json.dumps(ttv[0], indent=4))