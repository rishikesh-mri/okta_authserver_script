import os
import json
import requests
import copy
from dotenv import load_dotenv
from tkinter import ttk, StringVar, Label, messagebox
import tkinter as tk

load_dotenv()

OKTA_API_BASEURL = os.getenv('OKTA_API_BASEURL')
OKTA_API_TOKEN = os.getenv('OKTA_API_TOKEN')

#region User input
def get_object():
    global selected_type
    selected_type = combo.get()
    messagebox.showinfo(
        message=f"Please enter {selected_type} ID in the console"
    )
    main_window.destroy()
    return selected_type

main_window = tk.Tk()
main_window.config(width=300, height=200)

labelText=StringVar()
labelText.set("Application or Authorization Desired State?")
labelDir=Label(main_window, textvariable=labelText, height=4)
labelDir.pack(side='top')

main_window.title("Combobox")
combo = ttk.Combobox(
    state="readonly",
    values=['Authorization Server', 'Application'])
combo.place(x=50, y=50)

sendButton = tk.Button(main_window, text='Submit', command=get_object)
sendButton.place(x=50, y=100)

main_window.mainloop()


print('Enter okta id: ')
okta_id = input()
#endregion

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

application_obj = {
    'Application': {
        'Type': 'Spa',
        'InputObject': {
            'Label': 'test',
            'RedirectUri': [],
            'LogoutUri': []
        },
        'Group': []
    }
}

#region Authorization Server Desired State

#region helper functions
def get_basic_info():
    response = requests.get("{}/authorizationServers/{}".format(OKTA_API_BASEURL, okta_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})

    if(response.status_code == 200):
        return json.loads(response.text)
    else:
        raise ValueError(json.loads(response.text))
    
def get_scopes():
    response = requests.get("{}/authorizationServers/{}/scopes".format(OKTA_API_BASEURL, okta_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
    # response_dict = json.loads(response.text)

    if (response.status_code == 200):
        return json.loads(response.text)
    else:
        raise ValueError(json.loads(response.text))
    
def get_policies():
    response = requests.get("{}/authorizationServers/{}/policies".format(OKTA_API_BASEURL, okta_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
    # response_dict = json.loads(response.text)

    if (response.status_code == 200):
        return json.loads(response.text)
    else:
        raise ValueError(json.loads(response.text))
#endregion

def authorization_desired_state():
        # Fetch basic info
        basic_info_dict = get_basic_info()

        authserver_obj['AuthorizationServer']['InputObject']['Name'] = basic_info_dict['name']
        authserver_obj['AuthorizationServer']['InputObject']['Audience'] = basic_info_dict['audiences'][0]
        authserver_obj['AuthorizationServer']['InputObject']['Description'] = basic_info_dict['description']

        # Fetch scopes
        scope_dict = get_scopes()

        for scope in scope_dict:
            new_scope_obj = copy.deepcopy(scope_obj)
            new_scope_obj["InputObject"]["Name"] = scope['name']
            new_scope_obj["InputObject"]["Description"] = scope['description']
            new_scope_obj["InputObject"]["MetadataPublish"] = scope['metadataPublish']
            new_scope_obj["InputObject"]["DefaultScope"] = scope['default']
            authserver_obj["AuthorizationServer"]["Scope"].append(new_scope_obj)

        # Fetch policies
        policies_dict = get_policies()

        for policy in policies_dict:
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
            rulesFetch = requests.get("{}/authorizationServers/{}/policies/{}/rules".format(OKTA_API_BASEURL, okta_id, policy['id']), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
            rulesResponse = json.loads(rulesFetch.text)
            # fetch rules per policy
            for rule in rulesResponse:
                new_rules_obj = copy.deepcopy(rule_obj)
                new_rules_obj["Name"] = rule['name']
                new_rules_obj["GrantTypes"] = rule['conditions']['grantTypes']['include']
                new_rules_obj["Priority"] = rule['priority']
                new_rules_obj["Scopes"] = rule['conditions']['scopes']['include']
                rules.append(new_rules_obj)
            new_policy_obj['Rule'] = rules
            authserver_obj["AuthorizationServer"]["Policy"].append(new_policy_obj)

        # save json structure to file
        with open("{}.json".format(authserver_obj["AuthorizationServer"]["InputObject"]["Name"]), "w") as file:
            json.dump(authserver_obj, file, indent=4)

#endregion

#region Application Desired State
          
def application_desired_state():
    response = requests.get("{}/apps/{}".format(OKTA_API_BASEURL, okta_id), headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
    app = json.loads(response.text)

    try:
        application_obj['Application']['InputObject']['Label'] = app['label']
    except:
        pass

    try:
        application_obj['Application']['InputObject']['RedirectUri'] = app['settings']['oauthClient']['redirect_uris']
    except:
        pass

    try:
        application_obj['Application']['InputObject']['LogoutUri'] = app['settings']['oauthClient']['post_logout_redirect_uris']
    except:
        pass

    try:
        groups = set()
        groups_url = app['_links']['groups']['href']
        req = requests.get(groups_url, headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
        group_objs = json.loads(req.text)
        for group in group_objs:
            group_url = group['_links']['group']['href']
            group_request = requests.get(group_url, headers={"Authorization": "SSWS {}".format(OKTA_API_TOKEN)})
            group_list = json.loads(group_request.text)
            sub_group_name = group_list['profile']['name']
            if sub_group_name not in groups:
                groups.add(sub_group_name)

        if len(groups) > 0:
            application_obj['Application']['Group'] = list(groups)

    except:
        pass

    # save json structure to file
    with open("{}.json".format(application_obj['Application']['InputObject']['Label']), "w") as file:
        json.dump(application_obj, file, indent=4)

#endregion
    
if (selected_type == 'Application'):
    application_desired_state()
else:
    authorization_desired_state()