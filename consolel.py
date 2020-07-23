import time

def msgf(text):
    print("[%s] SERVER: %s"%(time.strftime("%c"),text))
    return "[Server] %s" % text

log_t_saved = 0

# open logcheck
def logop(text):
	global log_t_saved
	log_t_saved = time.time()
	print("{} LOG: {}".format(time.strftime("%c"),text),end="... ")

# end logcheck
def loged(text):
	print("{} ({})".format(text,time.time()-log_t_saved))