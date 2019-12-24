import base64, sys, os, json

def get_user_prefs():
  prefs = {}
  if os.path.exists(prefjspath):
    f = open(prefjspath, "r")
    prefs = json.loads(f.read())
    f.close()
  return prefs

def save_user_pref(prefname, prefval):
  h = os.path.expanduser('~')
  prefpath = h + "/.ucprefs"
  if not os.path.exists(prefpath):
    os.makedirs(prefpath)
  prefjspath =  prefpath + "/prefs"
  prefs = get_user_prefs()
  prefs[prefname] = prefpath
  f = open(prefjspath, "w")
  f.write(json.dumps(prefs))
  f.close()
