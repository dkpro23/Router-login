import requests,re,json,base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from urllib import parse
from config import username, password
from pprint import pprint
import warnings
import time
warnings.filterwarnings('ignore')

def randomWords(n):
    return get_random_bytes(n)
    
def base64url_escape(b64):
    out=""
    b64 = b64.decode('utf-8')
    for i in range(len(b64)):
        c = b64[i]
        if c == '+':
            out += '-'
        elif c == '/':
            out += '_'
        elif c == '=':
            out += '.'
        else:
            out += c
    return out.encode('utf-8')

def encrypt_post_data(pubkey, plaintext):
    aeskey = randomWords(16)
    iv = randomWords(16)
    pt = pad(plaintext.encode('utf-8'), AES.block_size)
    aes = AES.new(aeskey, AES.MODE_CBC, iv=iv)
    ct = aes.encrypt(pt)
    
    recipient_key = RSA.import_key(pubkey)
    rsa = PKCS1_OAEP.new(recipient_key)
    aesinfo = base64.b64encode(aeskey) + ' '.encode('utf-8') + base64.b64encode(iv)
    # aesinfo = aeskey + ' '.encode('utf-8') + iv
    ck = rsa.encrypt(aesinfo)
    return {
        'encrypted': '1',
        'ct': base64.urlsafe_b64encode(ct).decode('utf-8'),
        'ck': base64url_escape(base64.b64encode(ck)).decode('utf-8'),#base64.urlsafe_b64encode(ck).decode('utf-8'),
        }


def main():
    url = 'https://192.168.1.254/'
    with requests.Session() as session:
        cookies = {
            'admin': 'deleted',
            'lang': 'eng',
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }

        print(session.cookies.items())
        response = session.get(url, cookies=cookies, headers=headers, verify=False)
        print(response.status_code)
        print(response.headers)
        pubkey=re.findall(r"var pubkey = \'[\S\s]+\n\'",response.text)[0].split("'")[-2]
        pubkey = re.sub(r"\\","",pubkey)
        nonce=re.findall(r"var nonce = \"[\S]+\"",response.text)[0].split('"')[-2]
        token=re.findall(r"var token =\"[\S]+\"",response.text)[0].split('"')[-2]

        # print(pubkey,nonce,token)
        # print(response.cookies)
        # print(response.headers)


        dec_key = base64url_escape(base64.b64encode(randomWords(16)))
        dec_iv = base64url_escape(base64.b64encode(randomWords(16)))
        # dec_key = base64.urlsafe_b64encode(randomWords(16))
        # dec_iv = base64.urlsafe_b64encode(randomWords(16))

        postdata  = '&username=' + username + '&password=' + parse.quote(password) + '&csrf_token=' + token + '&nonce=' + nonce + '&enckey=' + dec_key.decode('utf-8') +'&enciv=' + dec_iv.decode('utf-8')
        
        data = encrypt_post_data(pubkey, postdata)
        print(data)
        print(session.cookies.items())
        cookies = {
            'admin': 'deleted',
            'lang': 'eng',
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0',
            'Accept': '*/*',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://192.168.1.254',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
        }
        time.sleep(5)
        response = session.post(url+'login.cgi', cookies=cookies, headers=headers, data=data, verify=False)
        print(response.status_code)
        print(response.headers)
        # print(response.cookies.items())
        # pprint(response.text)


if __name__ == '__main__':
    main()
