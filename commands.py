from database import Group as G
from consolel import *
from encryption import *

invites = G("invites")

def command(text, username, chatroom_name, db_chatrooms, admin):
    cmd = text[1:].split(" ")[0] # first word after /
    args = text[1:].split(" ")[1:] # command arguments

    if cmd == 'invite':
        if not admin:
            return msgf("You can't invite people because you are not an admin")
        if len(args) == 0:
            return msgf("Missing username")
        if len(args) == 1:
            if args[0] == username:
                return msgf("You can't invite yourself")
            db_chatrooms.add(chatroom_name+"_invited", ";".join(args)+";")
            if invites.get(args[0]) == None or chatroom_name+";" not \
            in invites.get(args[0]):
                invites.add(args[0], chatroom_name+";")
            return msgf("%s has been invited" % args[0])
        if len(args) > 1:
            db_chatrooms.add(chatroom_name+"_invited", ";".join(args)+";")
            for user_invited in args:
                if username != user_invited:
                    if invites.get(user_invited) == None or chatroom_name+";" not \
                        in invites.get(user_invited):
                            invites.add(user_invited, chatroom_name+";")
            return msgf("%s have been invited" % (", ".join(args[:-1])+" and "+args[-1]))
        if len(args) > 9:
            return msgf("Too many people to invite")
    elif cmd == 'checkadmin': # hidden
        return msgf("You are admin") if admin else msgf("You are not admin")
    elif cmd == 'delete':
        if not admin: 
            return msgf("You not the admin and you can't delete the chat")
        db_chatrooms.put(chatroom_name+"_messages", "")
        return msgf("Messages deleted")
    elif cmd == 'hash': # hidden
        return msgf("Hash: " + encrypt(" ".join(args)))
    else:
        return msgf("Unknown command")