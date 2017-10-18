[![Build Status](https://travis-ci.org/arthuroe/ShoppingList_API.svg?branch=master)](https://travis-ci.org/arthuroe/ShoppingList_API)
[![Coverage Status](https://coveralls.io/repos/github/arthuroe/ShoppingList_API/badge.svg?branch=master)](https://coveralls.io/github/arthuroe/ShoppingList_API?branch=master)
[![Code Climate](https://codeclimate.com/github/arthuroe/ShoppingList_API/badges/gpa.svg)](https://codeclimate.com/github/arthuroe/ShoppingList_API)

## SHOPPINGLIST API

Shoppinglist API allows users to register, login, create a shoppinglist and items to the list.


## Installation

Create a virtualenv, and activate it:

$ python3 -m venv shop

$ source shop/bin/activate

Install requirements:

$ pip install -r requirements.txt

Install postgresql

Create a database in postgresql

$ create database shopping_list

$ create user

## Run Migrations for the database

$ python manage.py db init

$ python manage.py db init

$ python manage.py db init

## Run tests on the code in the project folder with

$ Pytest

## Run the application

Run python run.py

To test this api use curl or postman(chrome extension) with the url below:

$ https://shoppinglist-api.herokuapp.com/

To view the documentation use the link below

$ http://docs.shoppinglist10.apiary.io/
