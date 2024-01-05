#!/bin/bash
# ARGS
# NSE "NSE_Query_String" 
# searchsploit "Query_String"
# MSF "MSF_Search_String"
# ENDARGS

# Updates: Uncomment if you want to update these.
# sudo apt update
# searchsploit -u
# msfupdate

# Assign arguments to variables
nse_query="$1"
searchsploit_query="$2"
msf_query="$3"

echo "------------------------------ NSE Script Search ------------------------------"
echo
echo
# Search for NSE scripts
echo "Searching for NSE scripts matching: $nse_query"
locate *.nse | grep "$nse_query"
echo
echo
echo "------------------------------ End of NSE Script Search ------------------------------"
echo
echo "------------------------------ Searchsploit Search ------------------------------"
echo
echo
# Search using searchsploit
echo "Searching locally in searchsploit for: $searchsploit_query"
searchsploit "$searchsploit_query" --disable-colour
echo
echo
echo "Searching in ExploitDB for: $searchsploit_query"
searchsploit -w "$searchsploit_query" --disable-colour
echo
echo "------------------------------ End of Searchsploit Search ------------------------------"
echo
echo "------------------------------ Metasploit Search ------------------------------"
echo
echo
# Search in Metasploit
echo "Searching in metasploit for: $msf_query"
msfconsole -q -x "search $msf_query; exit" | sed 's/\x1b\[[0-9;]*m//g'
echo
echo
echo "------------------------------ End of Metasploit Search ------------------------------"
