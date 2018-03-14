import os
from flask import Flask, request, abort, render_template, session
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import (
    FollowEvent, MessageEvent, BeaconEvent, TextMessage, TextSendMessage, LocationSendMessage
)
import psycopg2
from psycopg2.extras import DictCursor

from flask_bootstrap import Bootstrap
from flask_wtf.csrf import generate_csrf

import requests
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY')

bootstrap = Bootstrap(app)

line_bot_api = LineBotApi(os.environ.get('CHANNEL_ACCESS_TOKEN'))
handler = WebhookHandler(os.environ.get('CHANNEL_SECRET'))


@app.route("/coupon")
def doget():
    csrf_token = generate_csrf()
    session['X-CSRF'] = csrf_token
    data = {'channel_id': os.environ.get(
        'LOGIN_CHANNEL_ID'), 'csrf_token': csrf_token}
    return render_template('index.html', data=data)


@app.route("/login_callback")
def login_callback():
    code = request.args.get('code')
    state = request.args.get('state')

    if code is not None:
        callback = 'https://mtup-beacon.herokuapp.com/login_callback'
        url = 'https://api.line.me/oauth2/v2.1/token'
        response = requests.post(url,
                                 data={'grant_type': 'authorization_code',
                                       'code': code,
                                       'client_id': os.environ.get('LOGIN_CHANNEL_ID'),
                                       'client_secret': os.environ.get('LOGIN_CHANNEL_SECRET'),
                                       'redirect_uri': callback})
        access_token = response.json()['access_token']
        id_token = response.json()['id_token']
        decoded_id_token = jwt.decode(id_token,
                                      os.environ.get('LOGIN_CHANNEL_SECRET'),
                                      audience=os.environ.get(
                                          'LOGIN_CHANNEL_ID'),
                                      issuer='https://access.line.me',
                                      algorithms=['HS256'])

        if access_token is not None and state == session.get('X-CSRF'):
            html_file = ''
            if get_user_coupon_status(decoded_id_token['sub']):
                set_user_coupon_status(decoded_id_token['sub'], False)
                html_file = 'coupon.html'
            else:
                html_file = 'coupon_expired.html'
            return render_template(html_file)

    return render_template('error.html')


@app.route("/", methods=['POST'])
def callback():
    signature = request.headers['X-Line-Signature']

    body = request.get_data(as_text=True)
    app.logger.info("Request body: " + body)

    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)

    return 'OK'


@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    if event.message.text == 'beacon':
        if not get_user_visit(event.source.user_id):
            register_user_visit(event.source.user_id)

            set_user_coupon_status(event.source.user_id, True)
            line_bot_api.reply_message(
                event.reply_token,
                [
                    TextSendMessage(text="ご来店ありがとうございます􀂕"),
                    LocationSendMessage(
                        title='XXカフェXX店',
                        address='東京都新宿区111-1111',
                        latitude='35.688772',
                        longitude='139.701840'
                    ),
                    TextSendMessage(text="クーポンです􀁳"),
                    TextSendMessage(
                        text="􀀵ご注意􀀵リンクはお店の方に押して頂きますようお願いいたします􀀩"),
                    TextSendMessage(text='https://' +
                                    request.host + '/coupon'),
                ]
            )
    else:
        line_bot_api.reply_message(
            event.reply_token,
            [
                TextSendMessage(text="以下のリンク > 情報の提供から􀁷ビーコン􀁷をオン􀀭にしてご利用下さい􀁋"),
                TextSendMessage(text="line://nv/settings/privacy/"),
            ]
        )


@handler.add(BeaconEvent)
def handle_beacon(event):
    if event.beacon.type == "enter":
        if not get_user_visit(event.source.user_id):
            register_user_visit(event.source.user_id)
            set_user_coupon_status(event.source.user_id, True)
            line_bot_api.reply_message(
                event.reply_token,
                [
                    TextSendMessage(text="ご来店ありがとうございます􀂕"),
                    LocationSendMessage(
                        title='XXカフェXX店',
                        address='東京都新宿区111-1111',
                        latitude='35.688772',
                        longitude='139.701840'
                    ),
                    TextSendMessage(text="クーポンです􀁳"),
                    TextSendMessage(
                        text="􀀵ご注意􀀵リンクはお店の方に押して頂きますようお願いいたします􀀩"),
                    TextSendMessage(text='https://' +
                                    request.host + '/coupon'),
                ]
            )


@handler.add(FollowEvent)
def handle_follow(event):
    if not get_is_user_exists(event.source.user_id):
        register_user(event.source.user_id)
        line_bot_api.reply_message(
            event.reply_token,
            [
                TextSendMessage(
                    text="友だち追加ありがとう􀁺以下のリンク > 情報の提供から􀁷ビーコン􀁷をオン􀀭にしてご利用下さい􀁋"),
                TextSendMessage(text="line://nv/settings/privacy/"),
            ]
        )


def register_user(user_id):
    with psycopg2.connect(os.environ.get('DATABASE_URL'), sslmode='require') as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute('INSERT INTO users (user_id, has_visited, has_coupon) VALUES (pgp_sym_encrypt(\'{}\', \'{}\'), {}, {})'.format(
                user_id, os.environ.get('PYCRYPTO_KEY'), False, False))


def get_is_user_exists(user_id):
    with psycopg2.connect(os.environ.get('DATABASE_URL'), sslmode='require') as conn:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute('SELECT has_visited FROM users WHERE pgp_sym_decrypt(user_id, \'{}\') = \'{}\''.format(
                os.environ.get('PYCRYPTO_KEY'), user_id))
            return cur.fetchone() is not None


def get_user_visit(user_id):
    if get_is_user_exists(user_id):
        with psycopg2.connect(os.environ.get('DATABASE_URL'), sslmode='require') as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute('SELECT has_visited FROM users WHERE pgp_sym_decrypt(user_id, \'{}\') = \'{}\''.format(
                    os.environ.get('PYCRYPTO_KEY'), user_id))
                return cur.fetchone()['has_visited']


def register_user_visit(user_id):
    if get_is_user_exists(user_id):
        with psycopg2.connect(os.environ.get('DATABASE_URL'), sslmode='require') as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute('UPDATE users set has_visited = {} WHERE pgp_sym_decrypt(user_id, \'{}\') = \'{}\''.format(
                    True, os.environ.get('PYCRYPTO_KEY'), user_id))


def set_user_coupon_status(user_id, value):
    if get_is_user_exists(user_id):
        with psycopg2.connect(os.environ.get('DATABASE_URL'), sslmode='require') as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute('UPDATE users set has_coupon = {} WHERE pgp_sym_decrypt(user_id, \'{}\') = \'{}\''.format(
                    value, os.environ.get('PYCRYPTO_KEY'), user_id))


def get_user_coupon_status(user_id):
    if get_is_user_exists(user_id):
        with psycopg2.connect(os.environ.get('DATABASE_URL'), sslmode='require') as conn:
            with conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute('SELECT has_coupon FROM users WHERE pgp_sym_decrypt(user_id, \'{}\') = \'{}\''.format(
                    os.environ.get('PYCRYPTO_KEY'), user_id))
                return cur.fetchone()['has_coupon']


if __name__ == "__main__":
    app.debug = True
    app.run()
