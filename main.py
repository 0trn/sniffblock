# web
from flask import Flask
from flask import request
from flask import redirect
from flask import render_template
from flask import session
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import join_room, leave_room
# inter
import database as db
import verificators as verif
from commands import *
from encryption import *
import hashlib
import random
import time
from consolel import *

# database
db_auth = db.Group("accounts")
db_auth_verificators = db.Group("accounts_codes")
db_chatrooms = db.Group("chatrooms")
db_invites = db.Group("invites")
db_creations = db.Group("creations")

# config
port = 8080

# server inits
connectedpeople = 0

# helpers & inline shortcuts


def is_logged_in(request):
    # logop("Checking session")
    if 'logged_as' in session and 'auth_verification' in session:
        username = session['logged_as']
        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            ip = request.environ['REMOTE_ADDR']
        else:
            ip = request.environ['HTTP_X_FORWARDED_FOR']
        if db_auth_verificators.get(username + "_host") == encrypt(
                auth_salt + ip + auth_salt):
            return encrypt(session['logged_as'] + auth_salt) == session[
                "auth_verification"]
    # loged("done")
    return False


def is_invited(name):
    # logop("Checking invitation: %s" % name)
    check = session['logged_as'] + ";" in db_chatrooms.get(name + "_invited")
    # loged("done")
    return check


def error(msg):
    logop("Error: ")
    loged("%s" % msg)
    return render_template("error.html", message=msg)


# app & config
logop("Configuration")
app = Flask(__name__, template_folder="prep")
app.config.update(
    SECRET_KEY=hashlib.shake_128(str(random.getrandbits(128)).encode("utf-8"))
    .hexdigest(10))
socketio = SocketIO(app)
limiter = Limiter(app,
                  key_func=get_remote_address,
                  default_limits=["30/second"]
                  )
loged("done")


# routes
@app.route('/auth')
def auth():
    if is_logged_in(request):
        return redirect("/")
    return render_template("auth.html", salt = "AUTH")


@limiter.limit("1/second")  # anti-ddos, kind
@app.route('/')
def main():
    if not is_logged_in(request):
        return redirect("/auth")
    username = session["logged_as"]
    invites = []
    logop("Parsing invites")
    if db_invites.get(username) != None:
        for name in db_invites.get(username).split(";")[:-1]:
            try:
                invites.append({
                    "name": name,
                    "created_by": db_chatrooms.get(name + "_creator"),
                    "created_at": db_chatrooms.get(name + "_created_at"),
                    "messages": len(db_chatrooms.get(name + "_messages").split("\n"))
                })
            except:
                None  # account invited u was deleted
    loged("done")
    creations = []
    logop("Parsing creations")
    if db_creations.get(username) != None:
        for name in db_creations.get(username).split(";")[:-1]:
            creations.append({
                "name": name,
                "created_at": db_chatrooms.get(name + "_created_at"),
                "messages": len(db_chatrooms.get(name + "_messages").split("\n"))
            })
    loged("done")
    return render_template(
        "dashboard.html", username=session['logged_as'], invites=invites,
        creations=creations)


# static storage router
@app.route('/s/<path:path>')
def static_file(path):
    return app.send_static_file(path)


@limiter.limit("20/minute")
@app.route('/login', methods=['GET', 'POST'])
def login_check():
    if is_logged_in(request):
        loged("done")
        return redirect("/")
    if request.method == "GET":
        return redirect("/auth")
    logop("Checking login")
    username = request.form.get("username")
    password = request.form.get("password")
    if len(username) < 1 or len(password) < 1:
        return error("Enter some actual data first >:(")
    if db_auth.get(username) == sha512(password):
        session["logged_as"] = username
        session["auth_verification"] = encrypt(username + auth_salt)
        loged("done: [%s]" % username)
        return redirect("/")
    else:
        loged("fail")
        return error("Incorrect")


@app.route('/logout', methods=['GET'])
def logout():
    if is_logged_in(request):
        logop("Logging out")
        session.clear()
        loged("done")
    return redirect("/")


#@limiter.limit("5/hour")
@app.route('/register', methods=['GET', 'POST'])
def register():
    logop("New register")
    if is_logged_in(request):
        loged("already logged in")
        return redirect("/")
    if request.method == "GET":
        loged("GET: template rendered")
        return render_template("register.html")
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if password != confirmation:
        loged("passwords doesn't match")
        return error("Passwords doesn't match")
    if db_auth.get(username) != None:
        loged("already used username [%s] " % username)
        return error("The username is already used")
    if not verif.is_allowed(username):
        loged("invalid username")
        return error(
            "Invalid username! Please use only letters from a-z, A-Z or digits"
        )
    if len(username) < 3:
        loged("username too short")
        return error("Username too short!")
    if len(username) > 20:
        loged("username too long")
        return error("Username too long!")
    if len(password) < 4:
        loged("password too short")
        return error("Password too short! Use at least 5 characters. ")
    db_auth.put(username, sha512(password))
    db_auth_verificators.put(username, encrypt(username))
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ip = request.environ['REMOTE_ADDR']
    else:
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    db_auth_verificators.put(username + "_host",
                             encrypt(auth_salt + ip + auth_salt))
    loged("done")
    return redirect("/")


@app.route('/chat/<string:chatroom_name>')
def chatroom(chatroom_name):
    logop("Joining chat")
    if not is_logged_in(request):
        loged("not logged in")
        return redirect("/auth")
    chatroom_id = sha256(chatroom_name + "_chatroom")
    if db_chatrooms.get(chatroom_name + "_name") != None:
        if not is_invited(chatroom_name):
            loged("not invited")
            return error("You are not invited in this chatroom!")
        loged("done")
        return render_template(
            "chatroom.html",
            chatroom_name=chatroom_name,
            username=session['logged_as'],
            salt=db_chatrooms.get(chatroom_name + "_secret_salt"),
            usalt=salt,
        )
    else:
        loged("chatroom not found")
        return error("That chatroom doesn't exist!")

@app.route('/chat/create/')
def create_chatroom():
    logop("Attempt: creating null chat")
    loged("done")
    return error("A chatroom must have a name");

@app.route('/chat/create/<string:chatroom_name>')
def failed_attempt_create_chatroom(chatroom_name):
    logop("Creating chat")
    if not is_logged_in(request):
        loged("not logged in")
        return redirect("/auth")
    username = session['logged_as']
    if not verif.is_allowed(chatroom_name):
        loged("chatroom name invalid")
        return error("Invalid chatroom name!")
    if db_chatrooms.get(chatroom_name + "_name") != None:
        loged("already exists")
        return error("Chatroom already exists!")
    if len(chatroom_name) > 120:
        loged("name too long")
        return error("Chatroom name must have less than 121 characters!")
    chatroom_id = sha256(chatroom_name + "_chatroom")
    db_chatrooms.put(chatroom_name + "_name", chatroom_name)
    db_chatrooms.put(
        chatroom_name + "_messages",
        "[Server] Chatroom %s created! Invite people using the following command: /invite username\n[Server] After they are invited, you can share the link to the chat and talk with them!\n[Server] After you talk about secrets, clear the messages using /delete"
        % chatroom_name)
    db_chatrooms.put(chatroom_name + "_creator", username)
    db_chatrooms.put(chatroom_name + "_created_at", time.time())
    db_chatrooms.put(chatroom_name + "_invited", username + ";")
    db_chatrooms.put(chatroom_name + "_secret_salt",
                     encrypt(username + ":" + chatroom_name + ":" +
                             str(time.time())))
    db_creations.add(username, "%s;" % chatroom_name)
    loged("done")
    return redirect('/chat/%s' % chatroom_name)


@limiter.limit("25/second")
@app.route('/chat/getMessages:<string:chatroom_name>')
def get_chatroom(chatroom_name, methods=['GET']):
    key = db_chatrooms.get(chatroom_name + "_secret_salt")
    if not is_logged_in(request):
        return message_encrypt("Hidden! Please log in!", "server",
                               chatroom_name, key)
    if not is_invited(chatroom_name):
        return message_encrypt("You are not invited here!", "server",
                               chatroom_name, key)
    messages = db_chatrooms.get(chatroom_name + "_messages")
    messages = message_encrypt(messages, "server", chatroom_name, key)
    return messages


@socketio.on('joinedChat')
def chat_connect(data):
    chatroom_name = data["chatroom"]
    logop("Posting join message")
    if not is_logged_in(request):
        loged("not logged in")
        return redirect("/auth")
    if not is_invited(chatroom_name):
        loged("not invited here")
        return redirect("/auth")
    username = session['logged_as']
    sent_message = "%s joined the chat." % username
    messages = db_chatrooms.get(chatroom_name + "_messages").split("\n")[-99:]
    db_chatrooms.put(chatroom_name + "_messages", "\n".join(messages))
    db_chatrooms.add(chatroom_name + "_messages", "\n" + sent_message)
    # refresh for the first time
    socketio.emit("newMessage_%s" % chatroom_name)
    join_room(chatroom_name)
    loged("done")
    return '200'


@socketio.on("leftChat")
def chat_disconnect(data):
    chatroom_name = data["chatroom"]
    logop("Posting exit message")
    if not is_logged_in(request):
        loged("not logged in")
        return redirect("/auth")
    if not is_invited(chatroom_name):
        loged("not invited here")
        return redirect("/auth")
    username = session['logged_as']
    sent_message = "%s left the chat." % username
    messages = db_chatrooms.get(chatroom_name + "_messages").split("\n")[-99:]
    db_chatrooms.put(chatroom_name + "_messages", "\n".join(messages))
    db_chatrooms.add(chatroom_name + "_messages", "\n" + sent_message)
    # refresh for the first time
    socketio.emit("newMessage_%s" % chatroom_name)
    leave_room(chatroom_name)
    loged("done")
    return '200'


@socketio.on('postMessage')
def post_chatroom(data):
    chatroom_name = data["chatroom"]
    sent_message = data["message"]
    logop("Posting message")
    if not is_logged_in(request):
        loged("not logged in")
        return redirect("/auth")
    if not is_invited(chatroom_name):
        loged("not invited here")
        return redirect("/auth")
    username = session['logged_as']
    if len(sent_message) > 200:
        loged("message too long")
        return error("Message too long! Max 200 characters")
    key = db_chatrooms.get(chatroom_name + "_secret_salt")
    admin = username == db_chatrooms.get(chatroom_name + "_creator")
    message = message_decrypt(sent_message, username, 'server', key)
    messages = db_chatrooms.get(chatroom_name + "_messages").split("\n")[-99:]
    db_chatrooms.put(chatroom_name + "_messages", "\n".join(messages))
    db_chatrooms.add(chatroom_name + "_messages",
                     "\n[%s] %s" % (username, message.strip()))
    if message[0] == "/":
        return_point = command(
            message, username, chatroom_name, db_chatrooms, admin)
        db_chatrooms.add(chatroom_name + "_messages", "\n%s" % return_point)
    socketio.emit("newMessage_%s" % chatroom_name)  # refresh all messages
    loged("done")
    return '200'


@app.route('/destroy')
def destroy():
    logop("Destroying account")
    if not is_logged_in(request):
        loged("not logged in")
        return redirect("/auth")
    username = session['logged_as']
    db_auth.delete(username)
    db_auth_verificators.delete(username)
    db_auth_verificators.delete(username + "_host")
    db_invites.delete(username)
    if db_creations.get(username) != None:
        for name in db_creations.get(username).split(";")[:-1]:
            db_chatrooms.delete(name + "_created_at")
            db_chatrooms.delete(name + "_creator")
            db_chatrooms.delete(name + "_invited")
            db_chatrooms.delete(name + "_messages")
            db_chatrooms.delete(name + "_name")
            db_chatrooms.delete(name + "_secret_salt")
    db_creations.delete(username)
    loged("done")
    return redirect("/")

@app.route('/afk')
def afkError():
    return error("You are AFK.");

@socketio.on("connect")
# special events
@app.after_request
def add_security_headers(resp=None):
    if resp:
        logop("Adding sec headers: {}".format(request.url))
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-Powered-By'] = 'Python 3.6.6, Flask 1.1.2, Werkzeug 1.0.1'
        if "/chat/" not in request.url:
            resp.headers['Refresh'] = '300'
        return resp
        loged("done")
    else:
        return None


@app.errorhandler(429)
def rate_limited(e):
    return error("Rate limited")


@app.errorhandler(404)
def not_found(e):
    return error("Not found")


if __name__ == "__main__":
    logop("Starting app")
    socketio.run(app,
                 host='0.0.0.0', port=str(port), debug=False)
    loged("done")