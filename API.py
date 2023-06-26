import requests


client_id = 'e0a81c40a5124605aa031583d5cddbc0'
client_secret = '97971EE16486DFBB0A495CA2@AdobeOrg'


auth_url = 'https://ims-na1.adobelogin.com/ims/exchange/jwt'
api_url = 'https://your-adobe-api-url.com/api'


def get_access_token():
    # Generate JWT token
    jwt_token = generate_jwt_token()


    response = requests.post(auth_url, data={'client_id': client_id, 'client_secret': client_secret, 'jwt_token': jwt_token})


    access_token = response.json()['access_token']

    return access_token


def generate_jwt_token():
  
    import jwt
    import datetime

    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),  # Set the expiration time for the token
        'iss': client_id  # Set the issuer as your Adobe Cloud client ID
    }

    jwt_token = jwt.encode(payload, client_secret, algorithm='HS256')

    return jwt_token

def make_api_request(endpoint, data=None):
    access_token = get_access_token()

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    response = requests.post(f'{api_url}/{endpoint}', headers=headers, json=data)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        print(f'Error: {response.status_code}')
        return None

response_data = make_api_request('your-endpoint', data={'param1': 'value1', 'param2': 'value2'})
print(response_data)
