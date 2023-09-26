import os
import json
import requests
import copy
from dotenv import load_dotenv

load_dotenv()

OKTA_API_BASEURL = os.getenv('OKTA_API_BASEURL')
OKTA_API_TOKEN = os.getenv('OKTA_API_TOKEN')

print('Enter okta client id: ')
okta_client_id = input()

scope_obj = {
    "InputObject": {
        "Name": "",
        "Description": '',
        "MetadataPublish": "",
        "DefaultScope": False
    }
}

policy_obj = {
    "InputObject": {
        "Name": "",
        "Description": "",
        "Priority": 1,
        "Client": []
    },
    "Rule": []
}

rule_obj = {
    "Name": "anoter test",
    "GrantTypes": [],
    "Priority": 2,
    "Scopes": []
}

authserver_obj = {
    'AuthorizationServer': {
        'InputObject': {
            'Name': 'test',
            'Audience': '',
            'Description': 'test',
        },
        'Scope': [],
        'Policy': []
    }
}

# Fetch basic info
response = requests.get("{}/authorizationServers/{}".format(OKTA_API_BASEURL, okta_client_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
response_dict = json.loads(response.text)

authserver_obj['AuthorizationServer']['InputObject']['Name'] = response_dict['name']
authserver_obj['AuthorizationServer']['InputObject']['Audience'] = response_dict['audiences'][0]
authserver_obj['AuthorizationServer']['InputObject']['Description'] = response_dict['description']

# Fetch scopes
response = requests.get("{}/authorizationServers/{}/scopes".format(OKTA_API_BASEURL, okta_client_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
response_dict = json.loads(response.text)

for scope in response_dict:
    new_scope_obj = copy.deepcopy(scope_obj)
    new_scope_obj["InputObject"]["Name"] = scope['name']
    new_scope_obj["InputObject"]["Description"] = scope['description']
    new_scope_obj["InputObject"]["MetadataPublish"] = scope['metadataPublish']
    new_scope_obj["InputObject"]["DefaultScope"] = scope['default']
    authserver_obj["AuthorizationServer"]["Scope"].append(new_scope_obj)

# Fetch policies
response = requests.get("{}/authorizationServers/{}/policies".format(OKTA_API_BASEURL, okta_client_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
response_dict = json.loads(response.text)

for policy in response_dict:
    new_policy_obj = copy.deepcopy(policy_obj)
    new_policy_obj["InputObject"]["Name"] = policy['name']
    new_policy_obj["InputObject"]["Description"] = policy['description']
    new_policy_obj["InputObject"]["Priority"] = policy['priority']
    client_names = []
    for client_id in policy['conditions']['clients']['include']:
        if client_id != 'ALL_CLIENTS':
            fetchClient = requests.get("{}/apps/{}".format(OKTA_API_BASEURL, client_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
            client = json.loads(fetchClient.text)
            client_names.append(client['label'])
        else:
            client_names.append(client_id)

    new_policy_obj["InputObject"]["Client"] = client_names
    rules = []
    rulesFetch = requests.get("{}/authorizationServers/{}/policies/{}/rules".format(OKTA_API_BASEURL, okta_client_id, policy['id']), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
    rulesResponse = json.loads(rulesFetch.text)
    for rule in rulesResponse:
        new_rules_obj = copy.deepcopy(rule_obj)
        new_rules_obj["Name"] = rule['name']
        new_rules_obj["GrantTypes"] = rule['conditions']['grantTypes']['include']
        new_rules_obj["Priority"] = rule['priority']
        new_rules_obj["Scopes"] = rule['conditions']['scopes']['include']
        rules.append(new_rules_obj)
    new_policy_obj['Rule'] = rules
    authserver_obj["AuthorizationServer"]["Policy"].append(new_policy_obj)

with open("{}.json".format(authserver_obj["AuthorizationServer"]["InputObject"]["Name"]), "w") as file:
    json.dump(authserver_obj, file, indent=4)
# Fetch rules per policy