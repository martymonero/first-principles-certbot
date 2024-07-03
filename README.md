# FIRST PRINCIPLES CERTBOT

This is certbot example distilled down to the bare essentials. It automatically sets TXT Record via the name.com API allowing you to perform the dns-01 challenge.

Copy the .env.example to .env and change the values.

```
pip install -r requirements.txt
python get_cert.py -d example.org -d subdomain.example.org -d test.example.org

```

## TODO
- set DNS CAA : example.org. CAA 128 issue "letsencrypt.org"
- implement maximum waiting time
- implement own RSA and get rid of jwcrypto and cryptography spaceship libs :P


## DONE
- create new acme account if not exists
- allow multiple domains
- finish everything in one loop
- allow wildcard