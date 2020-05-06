run:
	./manage.py makemigrations && ./manage.py migrate && ./manage.py collectstatic --noinput && ./manage.py runserver