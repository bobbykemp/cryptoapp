# FancyDragon

![One Fancy Dragon](static/fancy_dragon.png)

## About:
[FancyDragon](https://fancydragon.herokuapp.com) is a very simple 'key manager' service. Create an account, create key pairs, and encrypt and decrypt UTF-8 encoded textual messages to and from other users of the app. You can also sign files, verify file signatures from others, and generate hashes of UTF-8 textual messages.

This application was originally developed for Dr. Levine's CSE 4381 Cryptography Class in Spring of 2020.

Please watch the demo video below to get an overview of the app's features. 

## Source:

https://github.com/bobbykemp/cryptoapp

## Technologies Used:
---
### Backend:
- [Django REST Framework (DRF)](https://www.django-rest-framework.org/)
    - Backend is a REST API written in Python using DRF
    - Serves the frontend (dynamically-rendered Django templates)
- [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
    PyCryptodome was the library used in the backend for:
    - Key generation
    - Encryption/decryption
    - Hashing
    - Any other cryptographic function used in these processes
---
### Frontend:
- Django templating, HTML, CSS, JS, and jQuery
---
### Hosting:
- [Heroku](https://www.heroku.com/about)
---

## Setting up the Project

### For local development

If you are setting the project up for local development, you will likely need to install the pg_config executable as this project makes use of postgres as its database. pg_config can be found in libpq-dev on Debian/Ubuntu, or libpq-devel on Centos/Fedora/Cygwin.

You will also likely need to run the following commands in order to install the necessary dependencies to run the project locally (i.e. gcc, python-dev packages, etc.): 
```python
pip install psycopg2-binary
```
```
apt install build-essential
```

```
apt install python3-dev
```

You will also need to create a file called ".env" at the root of the project (next to manage.py). This file allows for dynamic configuration of some of Django's settings. For local testing, these are the settings you will most likely want, as they are the least-restricitve security-wise:
```python
SECRET_KEY="testing"
DEBUG=True
CSRF_COOKIE_SECURE=False
SESSION_COOKIE_SECURE=False
SECURE_CONTENT_TYPE_NOSNIFF=False
SECURE_BROWSER_XSS_FILTER=False
SECURE_SSL_REDIRECT=False
```