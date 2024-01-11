#!/usr/bin/bash

// JuNeDNSAPI-acme - 2024 - Eduardo Ruiz Moreno
#https://github.com/acmesh-official/acme.sh/wiki/DNS-API-Dev-Guide

# Add to account.conf
#JUNEDNSAPI_URL='http://localhost:9053'
#JUNEDNSAPI_APIKEY=''

function _get_root() {
	IFS="." PS=($1)
	CNT=${#PS[@]}
	echo ${PS[$CNT-2]}.${PS[$CNT-1]}
}

dns_junednsapi_add() {
	fulldomain=$1
	txtvalue=$2

	if [ -z "$JUNEDNSAPI_URL" ] || [ -z "$JUNEDNSAPI_APIKEY" ]; then
    		_err "You don't specify JuNeDNS API parameters"
		return 1
	fi

	d=$(_get_root $fulldomain)
	curl -X POST -d '{"name": "$fulldomain", "type": "TXT", "content": "\"$txtvalue\""}' $JUNEDNSAPI_URL/api/$JUNEDNSAPI_APIKEY/$d
	return 0
}

dns_junednsapi_rm() {
	fulldomain=$1
	txtvalue=$2
#	curl -X DELETE $JUNEDNSAPI_URL/api/$JUNEDNSAPI_APIKEY/$fulldomain/TXT
	return 0
}
