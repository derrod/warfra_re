import requests
import json

s = requests.session()

WF_ARSENAL_ID = 'ud1zj704c0eb1s553jbkayvqxjft97'
GQL_QUERY = '''query ExtensionsForChannel($channelID: ID!) {
  user(id: $channelID) {
    id
    channel {
      id
      selfInstalledExtensions {
        ...extensionInstallationSelfEdge
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment extensionInstallationSelfEdge on ExtensionInstallationSelfEdge {
  token {
    extensionID
    jwt
    __typename
  }
  issuedAt
  __typename
}
'''


def get_token_gql(channel_id):
    body = {
        'operationName': 'ExtensionsForChannel',
        'query': GQL_QUERY,
        'variables': {
            'channelID': str(channel_id)
        },
        'extensions': {}
    }
    extra_headers = {
        'client-id': 'kimne78kx3ncx6brgo4mv6wki5h1ko'
    }

    r = s.post('https://gql.twitch.tv/gql', json=body, headers=extra_headers)
    j = r.json()
    
    # find WF extension in response, then get token
    for ext in j['data']['user']['channel']['selfInstalledExtensions']:
        if ext['token']['extensionID'] == WF_ARSENAL_ID:
            return ext['token']['jwt']  
    else:
        raise ValueError('WF extension not found')


def get_token_v5(channel_id):
    extra_headers = {
        'client-id': 'b31o4btkqth5bzbvr9ub2ovr79umhh'
    }
    r = s.get(f'https://api.twitch.tv/v5/channels/{channel_id}/extensions', headers=extra_headers)
    j = r.json()
    
    for token in j['tokens']:
        if token['extension_id'] == WF_ARSENAL_ID:
            return token['token']
    else:
        raise ValueError('WF extension not found')


if __name__ == '__main__':
    # This just needs to be a channel with the extension enabled to serve as a "token donor".
    # Doesn't need to be online or match the username we're fetching data for.
    channel_id = 95178769  # ladytheladdy
    # Warframe profile to fetch, note that the username needs to be all lowercase once the request goes out
    warframe_profile = '[DE]Kickbot'.lower()
    
    # Either works, although in theory GQL may be the more future proof variant
    token = get_token_gql(channel_id)
    # token = get_token_v5(channel_id)
    
    extra_headers = {
        'Origin': 'https://ud1zj704c0eb1s553jbkayvqxjft97.ext-twitch.tv',
        'Referer': 'https://ud1zj704c0eb1s553jbkayvqxjft97.ext-twitch.tv/',
        'Authorization': f'Bearer {token}'
    }
    r = s.get('https://content.warframe.com/dynamic/twitch/getActiveLoadout.php',
              params=dict(account=warframe_profile), headers=extra_headers)

    if r.status_code == 204:
        print('User has loadout sharing disabled.')
    else:
        print(json.dumps(r.json(), sort_keys=True, indent=2))
