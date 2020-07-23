import markupsafe as ms

allowed_chars = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def is_allowed(text):
	for i in text:
		if i not in allowed_chars:
			return False
	return True