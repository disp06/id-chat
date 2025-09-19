# ID SECRET CHAT

A simple, anonymous web chat with the ability to create private rooms and exchange encrypted messages and files.

## Description

This project implements a web application for anonymous real-time communication using Flask and Flask-SocketIO. Users can create and join rooms, and exchange messages or files. Messages are stored only in memory on the server and are automatically deleted after an hour of inactivity.

## Key Features

- Create unique rooms for private communication
- Real-time text messaging
- File transfer between room participants
- Automatic cleaning of inactive rooms and removal of uploaded files
- Simple and intuitive web page with an HTML/CSS/JS interface


## Start

``
 git clone https://github.com/disp06/id-chat.git
``

``
cd id-chat
``

``
pip install -r requirements.txt
``

``
Python app.py
``


Enter on web:
http://localhost:5537
