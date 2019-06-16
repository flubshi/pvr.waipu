import xbmc
import xbmcgui
import inputstreamhelper
import requests
import json


def getStatus():
	url = "https://status.wpstr.tv/status?nw=wifi"
	try:
	  r = requests.get(url)
	except requests.ConnectionError:
	  return {"statusText" : "No internet connection!"}
	return r.json()

is_helper = inputstreamhelper.Helper('mpd', drm='com.widevine.alpha')
if is_helper.check_inputstream():
	# widevine installed;
	xbmc.log("[pvr.waipu] widevine: installed", level=xbmc.LOGDEBUG)
	widevine_status = "OK - Widevine found."
else:
	# widevine not installed; notify user
	xbmc.log("[pvr.waipu] widevine: not installed", level=xbmc.LOGDEBUG)
	widevine_status = "Error - Not found!"
	
network_status_arr = getStatus()
network_status = network_status_arr["statusText"]

xbmcgui.Dialog().ok("pvr.waipu - Requirements", "[B]Widevine:[/B] " + widevine_status, "", "[B]Network status:[/B] " + network_status)

