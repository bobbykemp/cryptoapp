# FancyDragon

![One Fancy Dragon](static/fancy_dragon.png)

## About:
[FancyDragon](fancydragon.herokuapp.com) is a very simple 'key manager' service. Create an account, create key pairs, and encrypt and decrypt utf-8 encoded textual messages to and from other users of the app. You can also sign files, verify file signatures from others, and generate hashes of utf-8 textual messages.

This application was developed for Dr. Levine's CSE 4381 Cryptography Class in Spring of 2020.

Please watch the demo video below to see how to use this application. 

## Sources:
---
### Backend:
- [Django REST Framework (DRF)](https://www.django-rest-framework.org/)
    DRF was used on top of Django; the app is built as a web API with an endpoint for each main feature
- [Django](https://www.djangoproject.com/)
    Django was used as a base for DRF
- [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
    PyCryptodome was the library used in the backend for:
    - key generation
    - encryption/decryption
    - hashing
    - any other cryptographic function used in these processes
---
### Frontend:
- Aside from HTML, CSS and vanilla JS, [jQuery](https://jquery.com/) was also used
---
### Hosting:
- [Heroku](https://www.heroku.com/about)
---