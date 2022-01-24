#!/usr/bin/python3
import requests
import json
import time
import datetime
import ipaddr
#import urllib3
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

######CF
auth_email="xpto@xpto.com"
auth_key="000000000000000"
time_zone_d = datetime.timedelta(minutes=180) # DIferença da sua timezone pra da cloudflare
######CF
cf_headers = {
	'X-Auth-Email': auth_email,
	'X-Auth-Key'  : auth_key,
	'Content-Type': 'application/json',
}
proxies = {}
#proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
verify = True
#verify = False
cf_banned_ips = []

def cf_get_events(minutes):
	data = '{"operationName": "ActivityLogQuery","variables": { "zoneTag": "000000000000000", "filter": { "AND": [{ "datetime_geq": "%s", "datetime_leq": "%s" }, { "OR": [{ "action": "managed_challenge" }, { "action":"block" }] }, { "AND": [{ "action_neq": "challenge_solved" }, { "action_neq": "challenge_failed" }, { "action_neq": "challenge_bypassed" }, { "action_neq": "jschallenge_solved" }, { "action_neq": "jschallenge_failed" }, { "action_neq": "jschallenge_bypassed" }, { "action_neq": "managed_challenge_skipped" }, { "action_neq": "managed_challenge_non_interactive_solved" }, { "action_neq": "managed_challenge_interactive_solved" }, { "action_neq": "managed_challenge_bypassed" }, { "OR": [{ "ruleId_like": "999___" }, { "ruleId_like": "900___" }, { "ruleId": "981176" }, { "AND": [{ "ruleId_notlike": "9_____" }, { "ruleId_notlike": "uri-9_____" }] }] }] }] }, "limit": 1000, "activityFilter": { "AND": [{ "datetime_geq": "%s", "datetime_leq": "%s" }, { "ruleId_neq": "000000000000000" }, { "ruleId_neq": "000000000000000" }, { "ruleId_neq": "000000000000000" }, { "ruleId_neq": "000000000000000" }, { "AND": [{ "action_neq": "challenge_solved" }, { "action_neq": "challenge_failed" }, { "action_neq": "challenge_bypassed" }, { "action_neq": "jschallenge_solved" }, { "action_neq": "jschallenge_failed" }, { "action_neq": "jschallenge_bypassed" }, { "action_neq": "managed_challenge_skipped" }, { "action_neq": "managed_challenge_non_interactive_solved" }, { "action_neq": "managed_challenge_interactive_solved" }, { "action_neq": "managed_challenge_bypassed" }, { "OR": [{ "ruleId_like": "999___" }, { "ruleId_like": "900___" }, { "ruleId": "981176" }, { "AND": [{ "ruleId_notlike": "9_____" }, { "ruleId_notlike": "uri-9_____" }] }] }] }] }},"query": "query ActivityLogQuery($zoneTag: string, $filter: FirewallEventsAdaptiveGroupsFilter_InputObject, $activityFilter: FirewallEventsAdaptiveFilter_InputObject, $limit: int64!) {viewer { zones(filter: { zoneTag: $zoneTag }) { total: firewallEventsAdaptiveByTimeGroups(limit: 1, filter: $filter) { count avg { sampleInterval __typename } __typename } activity: firewallEventsAdaptive(filter: $activityFilter, limit: $limit, orderBy: [datetime_DESC, rayName_DESC, matchIndex_ASC]) { action clientIP clientRequestPath clientRequestQuery datetime rayName ruleId source userAgent __typename } __typename } __typename}}"}'
	s = datetime.datetime.now() - datetime.timedelta(minutes=minutes) + time_zone_d
	s = s.isoformat("T") + "Z"
	e = datetime.datetime.now() + time_zone_d
	e = e.isoformat("T") + "Z"
	data = data % (s,e,s,e)
	url = "https://api.cloudflare.com/client/v4/graphql"
	r = requests.post(url, headers=cf_headers, data=data, proxies=proxies, verify=verify)
	return json.loads(r.text)['data']['viewer']['zones'][0]['activity']

def cf_ban_ip(ip):
	if(":" in ip):
		ip = ipaddr.IPv6Address(ip).exploded
	if(ip in cf_banned_ips):
		print(ip+" Alread Banned")
		return True
	print("Banning "+ip)
	url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules"
	data = {"mode": "block",
		"configuration": {
			"target": 'ip',
			"value": ip
		},
		"notes": "cf_ban_cartas"
	}
	r = requests.post(url, headers=cf_headers, json=data, proxies=proxies, verify=verify)

def cf_get_banned_ips():
	url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?notes=cf_ban_cartas&per_page=1000"
	r = requests.get(url, headers=cf_headers, proxies=proxies, verify=verify)
	ret = {}
	r = json.loads(r.text)['result']
	for x in r:
		ret[x['id']] = x['created_on']
		if(x['configuration']['target'] == 'ip6'):
			x['configuration']['value'] = ipaddr.IPv6Address(x['configuration']['value']).exploded
		cf_banned_ips.append(x['configuration']['value'])
	return ret

def cf_delete_ban(id):
	print("unbanning "+id)
	url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/{0}".format(id)
	r = requests.delete(url, headers=cf_headers, proxies=proxies, verify=verify)

cf_bans = cf_get_banned_ips()
block = []
count = {}
for cf_f_event in cf_get_events(35):#How many minutes of firewall events the script will analyze, i run it every 30 minutes on crontab, so i check 35 minutes of events
	if(cf_f_event['action'] == 'block'):
		if(not cf_f_event['clientIP'] in block):
			block.append(cf_f_event['clientIP'])
			cf_ban_ip(cf_f_event['clientIP'])
	else:
		if(cf_f_event['clientIP'] in count):
			count[cf_f_event['clientIP']] = count[cf_f_event['clientIP']] + 1
		else:
			count[cf_f_event['clientIP']] = 1

for ip in count:
	if(count[ip] > 5):
		cf_ban_ip(ip)

e = datetime.datetime.now() - datetime.timedelta(minutes=180)#How much time the block will last

for banned_id in cf_bans:
	create = cf_bans[banned_id]
	create = datetime.datetime.strptime(create[0:19], '%Y-%m-%dT%H:%M:%S') - time_zone_d
	if(create < e):
		cf_delete_ban(banned_id)
