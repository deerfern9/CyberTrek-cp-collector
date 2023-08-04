import threading
import time
from datetime import datetime
import requests
from web3 import Web3
from eth_account.messages import encode_defunct

use_proxy = int(input('Use proxy? 0/1: '))
rpc = "https://bsc.blockpi.network/v1/rpc/1fee6969f7509047a495cc27cbb9158dcd15c088"
w3 = Web3(Web3.HTTPProvider(rpc))

headers = {
    'authority': 'api.cyberconnect.dev',
    'accept': '*/*',
    'accept-language': 'en-GB,en;q=0.9,uk-UA;q=0.8,uk;q=0.7,ru-RU;q=0.6,ru;q=0.5,en-US;q=0.4',
    'content-type': 'application/json',
    'origin': 'https://link3.to',
    'referer': 'https://link3.to/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
}


def read_file(filename):
    result = []
    with open(filename, 'r') as file:
        for tmp in file.readlines():
            result.append(tmp.replace('\n', ''))

    return result


def write_to_file(filename, text):
    with open(filename, 'a') as file:
        file.write(f'{text}\n')


def get_nonce(address, proxy):
    json_data = {
        'query': '\n    mutation nonce($address: EVMAddress!) {\n  nonce(request: {address: $address}) {\n    status\n    message\n    data\n  }\n}\n    ',
        'variables': {
            'address': address,
        },
        'operationName': 'nonce',
    }

    response = requests.post('https://api.cyberconnect.dev/profile/', headers=headers, json=json_data, proxies=proxy)
    nonce = response.json()['data']['nonce']['data']
    return nonce


def sign_signature(private_key, message):
    message_hash = encode_defunct(text=message)
    signed_message = w3.eth.account.sign_message(message_hash, private_key)

    signature = signed_message.signature.hex()
    return signature


def get_auth_token(address, message, signature, proxy):
    json_data = {
        'query': '\n    mutation login($address: EVMAddress!, $signature: String!, $signedMessage: String!, $token: String, $isEIP1271: Boolean, $chainId: Int) {\n  login(\n    request: {address: $address, signature: $signature, signedMessage: $signedMessage, token: $token, isEIP1271: $isEIP1271, chainId: $chainId}\n  ) {\n    status\n    message\n    data {\n      id\n      privateInfo {\n        address\n        accessToken\n        kolStatus\n      }\n    }\n  }\n}\n    ',
        'variables': {
            'signedMessage': message,
            'token': '',
            'address': address,
            'chainId': 56,
            'signature': signature,
            'isEIP1271': False,
        },
        'operationName': 'login',
    }

    resp = requests.post('https://api.cyberconnect.dev/profile/', headers=headers, json=json_data, proxies=proxy).json()
    try:
        token = resp['data']['login']['data']['privateInfo']['accessToken']
        return token
    except:
        print(resp)


def claim_cp(address ,authorization, proxy):
    private_headers = headers.copy()
    private_headers['authorization'] = authorization

    '''  UPDATING INFO ABOUT CLAIMING  '''
    json_data = {
        'query': '\n    query checkV3RewardEligibility {\n  earlyAccess: checkV3RewardsEligibility(input: {rewardType: EARLY_ACCESS}) {\n    status\n    raffleStatus\n    claimStatus\n    signupStatus\n  }\n  miniShard: checkV3RewardsEligibility(input: {rewardType: MINISHARD}) {\n    status\n    raffleStatus\n    claimStatus\n    signupStatus\n  }\n  raffle: checkV3RewardsEligibility(input: {rewardType: RAFFLE}) {\n    status\n    raffleStatus\n    claimStatus\n    signupStatus\n  }\n  points: checkV3RewardsEligibility(input: {rewardType: POINT}) {\n    status\n    raffleStatus\n    claimStatus\n    signupStatus\n  }\n  countV3CampaignCyberPoint {\n    count\n    total\n  }\n}\n    ',
        'operationName': 'checkV3RewardEligibility',
    }

    claiming_info = requests.post(
        'https://api.cyberconnect.dev/profile/',
        headers=private_headers,
        json=json_data,
        proxies=proxy
    ).json()['data']['points']

    '''   CLAIMING CYBER_POINTS   '''
    if claiming_info['status'] == 'ALL_MEET' and claiming_info['claimStatus'] == 'NOT_CLAIMED':
        json_data = {
            'query': '\n    mutation claimCyberPoint($outId: String!) {\n  claimCyberPoint(input: {outId: $outId}) {\n    status\n  }\n}\n    ',
            'variables': {
                'outId': 'v3_campaign',
            },
            'operationName': 'claimCyberPoint',
        }

        response = requests.post('https://api.cyberconnect.dev/profile/', headers=private_headers, json=json_data).json()['data']['claimCyberPoint']

        print(f'{datetime.now().strftime("%d %H:%M:%S")} | {address} | Claiming status: {response["status"]}')
    else:
        print(f'{datetime.now().strftime("%d %H:%M:%S")} | {address} | Some error: {claiming_info}')


def main(private, proxy):
    address = w3.eth.account.from_key(private).address
    proxy = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    nonce = get_nonce(address, proxy)
    message = f'''link3.to wants you to sign in with your Ethereum account:\n{address}\n\n\nURI: https://link3.to\nVersion: 1\nChain ID: 56\nNonce: {nonce}\nIssued At: 2023-03-19T14:04:18.580Z\nExpiration Time: 2023-04-02T14:04:18.580Z\nNot Before: 2023-03-19T14:04:18.580Z'''
    sign = sign_signature(private, message)
    accessToken = get_auth_token(address, message, sign, proxy)
    claim_cp(address, accessToken, proxy)


def main_2():
    privates = read_file('privates.txt')
    if use_proxy:
        proxies = read_file('proxies.txt')
    else:
        proxies = [None] * len(privates)
    '''SLOW'''
    for private, proxy in zip(privates, proxies):
        main(private,proxy)

    '''FAST'''
    # i = 0
    #
    # for j in range(int(len(privates)/20)+1):
    #     for k in range(20):
    #         try:
    #             threading.Thread(target=main, args=(privates[i], proxies[i])).start()
    #             i += 1
    #         except Exception as e:
    #             print(e)
    #     time.sleep(1)


if __name__ == '__main__':
    main_2()
