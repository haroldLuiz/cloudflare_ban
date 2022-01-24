# cloudflare_ban

By default, specially on the PRO plan, i could not find a way to block by X time IPs blocked by the waf, or IPs triggering my custom firewall rules, so i created this script that uses cloudflare API to check offenders and block them for 3 hours.

I recomend generating/copyng the graphql query from your own firewall overview, (inpect element/network tab) https://dash.cloudflare.com/XXXXXXX/xxx.com/firewall

This script is not optimized and provided as is, it works for my needs on my server.i check github rarely so dont expect me to maintain it. You can use it as i am providing with a few changes/configurations, fix it to actually be a decent script, sell or do watever you want to, credits would be apreciated.
