run:
	./manage.py makemigrations && ./manage.py migrate && ./manage.py collectstatic && ./manage.py runserver