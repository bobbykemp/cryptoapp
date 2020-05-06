release: python ./cryptoapp/manage.py migrate
web: gunicorn --pythonpath cryptoapp cryptoapp.wsgi