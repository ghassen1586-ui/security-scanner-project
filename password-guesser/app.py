from flask import Flask, request, Response
import pickle
import random
import re
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
from collections import Counter

app = Flask(__name__)

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)
print("Model loaded from file")


def generate_password(seed, order=2, max_length=16):
    result = seed
    context = result[-order:] if len(result) >= order else '~' * (order - len(result)) + result
    while len(result) < max_length:
        choices = model.get(context)
        if not choices:
            break
        next_char = random.choices(list(choices.keys()), weights=choices.values())[0]
        if next_char == '~':
            break
        result += next_char
        context = result[-order:]
    return result


def apply_reinforcement(password, order=2):
    padded = '~' * order + password + '~'
    for i in range(len(padded) - order):
        context = padded[i:i+order]
        next_char = padded[i+order]
        model[context][next_char] += 1


STOPWORDS = {
    'the', 'and', 'is', 'in', 'at', 'of', 'a', 'to', 'for', 'on', 'with',
    'as', 'by', 'an', 'be', 'this', 'that', 'it', 'from', 'or', 'are',
    'was', 'were', 'has', 'have', 'had', 'not', 'but', 'you', 'your',
    'we', 'our', 'us', 'can', 'will', 'if', 'do', 'does', 'all', 'about',
    'their', 'click', 'here'
}


def mine_words(url, top_n=15):
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}
    response = requests.get(url, headers=headers, timeout=5)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')
    for tag in soup(['script', 'style']):
        tag.decompose()

    text = soup.get_text(separator=' ')
    words = re.findall(r'[a-zA-Z]{3,}', text)
    words = [w.lower() for w in words if w.lower() not in STOPWORDS]

    counts = Counter(words)
    return [word for word, _ in counts.most_common(top_n)]


SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"


def make_soap_response(body_xml):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="{SOAP_NS}">
  <soap:Body>
    {body_xml}
  </soap:Body>
</soap:Envelope>'''


@app.route('/soap', methods=['POST'])
def soap_endpoint():
    key = request.headers.get('X-API-Key')
    if not key or key not in ['secu-demo-key-2026']:
        return Response(make_soap_response('<error>Missing or invalid API key</error>'), mimetype='text/xml', status=401)
    root = ET.fromstring(request.data)
    body = root.find('{%s}Body' % SOAP_NS)
    operation = list(body)[0]
    op_name = operation.tag.split('}')[-1]

    if op_name == 'generate':
        seed = operation.find('seed').text or ''
        candidates = list(set(generate_password(seed) for _ in range(15)))
        candidates_xml = ''.join(f'<candidate>{c}</candidate>' for c in candidates)
        response_body = f'<generateResponse>{candidates_xml}</generateResponse>'
        return Response(make_soap_response(response_body), mimetype='text/xml')

    elif op_name == 'reinforce':
        password = operation.find('password').text or ''
        apply_reinforcement(password)
        with open('model.pkl', 'wb') as f:
            pickle.dump(model, f)
        response_body = f'<reinforceResponse><status>learned</status><password>{password}</password></reinforceResponse>'
        return Response(make_soap_response(response_body), mimetype='text/xml')

    elif op_name == 'mine':
        url = operation.find('url').text or ''
        try:
            words = mine_words(url)
        except requests.exceptions.RequestException as e:
            return Response(make_soap_response(f'<error>Could not reach target: {e}</error>'), mimetype='text/xml', status=502)
        words_xml = ''.join(f'<word>{w}</word>' for w in words)
        response_body = f'<mineResponse>{words_xml}</mineResponse>'
        return Response(make_soap_response(response_body), mimetype='text/xml')

    return Response(make_soap_response('<error>Unknown operation</error>'), mimetype='text/xml', status=400)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)