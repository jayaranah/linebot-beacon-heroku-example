Example of LINE Bot with LINE Beacon on Heroku

## Prepare
* Upload to Heroku
* Set config vars
    * CHANNEL_SECRET - Channel secret of Bot(Messaging API enabled account)
    * CHANNEL_ACCESS_TOKEN - Channel access token of Bot(Messaging API enabled account)
    * LOGIN_CHANNEL_ID - Channel ID of LINE Login Channel
    * LOGIN_CHANNEL_SECRET - Channel secret of LINE Login Channel
    * PYCRYPTO_KEY - Key to encrypt user_id
    * APP_SECRET_KEY - Key to generate CSRF Token
* Provision Heroku Postgres Add-on
* Provision pgcrypto
```bash
$ heroku pg:psql --app YOUR_APP_NAME
YOUR_APP_NAME::DATABASE=> create extension pgcrypto;
```
* Create table
```bash
YOUR_APP_NAME::DATABASE=> create table users(user_id bytea primary key, has_visited boolean, has_coupon boolean);
```
