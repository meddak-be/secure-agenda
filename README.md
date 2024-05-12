# Readme

Developed by Mohammed Eddak & Ayoub B.

This repository contains a secure online agenda written in Python using Django web framework. The main purpose is the create a fully online secure application.  

You will find a pdf report containing all the security features implemented and a little overview of the app interface on the root of this repository.

Getting started

This project has been build with the following versions:

- Python 3.10.7
- django 4.1.5
- django-crispy-forms 1.14.0
- pycryptodome 3.16.0
- pyotp 2.8.0
- logtail-python 0.1.3

a requirements.txt file has been provided to install the package

The following command must be typed to install the necessary packages

```jsx
pip install -r requirements.txt
```

The django project can be exectued and be visible only in the machine or locally in the network

1. To execute the project only for locally inside the machine (On Linux and MacOS X):

```jsx
python3 manage.py runserver
```

On Windows

```jsx
py manage.py runserver
```

The web app will be executed and be accessible in the following link : [http://127.0.0.1:8000](http://127.0.0.1:8000) if the port is already in use, another port will be assigned and it will be shown in the terminal. It is also possible to specify a port 

```jsx
python3 manage.py runserver 127.0.0.1:8001
```

In this case the web app will be accessible in the following link : [http://127.0.0.1:8001](http://127.0.0.1:8000)

2. For executing the project in the local network the following command must be executed :

```jsx
python3 manage.py runserver 0.0.0.0:8000
```

it will execute the web app on port 8000 and will be accessible by all the devices inside the network. We must know the local IP address of the device in order to access the web app. To do so ifconfig can be used to find this address.

extra:

For the logs, we use an external services : [https://betterstack.com/logtail](https://betterstack.com/logtail) 


