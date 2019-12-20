#!/usr/bin/env python
from netmiko import Netmiko
from getpass import getpass
import textwrap as _textwrap
import argparse
import re
import sys

class MultilineFormatter(argparse.HelpFormatter):
    def _fill_text(self, text, width, indent):
        # text = self._whitespace_matcher.sub(' ', text).strip()
        paragraphs = text.split('|n ')
        multiline_text = ''
        for paragraph in paragraphs:
            formatted_paragraph = _textwrap.fill(paragraph, width, initial_indent=indent, subsequent_indent=indent) + '\n'
            multiline_text = multiline_text + formatted_paragraph
        return multiline_text

def present(word, line):
    tmpWords = line.split(" ")
    tmpPresent = word in tmpWords
    if not tmpPresent:
        tmpPresent |= "{}\n".format(word) in tmpWords
        if not tmpPresent:
            tmpPresent |= "{}/32".format(word) in tmpWords
            if not tmpPresent:
                tmpPresent |= "{}/32\n".format(word) in tmpWords
    return tmpPresent

def getcommands(ipaddress, bBan, bWhitelist, bRemove, strInit, connection):
    strMsg = ""
    strCommand = 'show configuration policy-options | display set | match {} | match "wazuh\..*list"'.format(ipaddress)
    prompt = connection.find_prompt()
    result = connection.send_command(strCommand)
    bPresent = present(ipaddress, result)
    if bPresent:
            bInWhitelist = present("wazuh.whitelist", result)
            bInBlacklist = present("wazuh.blacklist", result)
    else:
        bInWhitelist = bInBlacklist = False
    strCommands = ""
    if bBan:
        if not bInWhitelist:
            strCommands += "set policy-options prefix-list wazuh.blacklist {}\n".format(ipaddress)
        else:
            strMsg = "{} is whitelisted. Can't ban it!\n".format(ipaddress)
    elif bWhitelist:
        if bInBlacklist:
            tmpWords = result.split(" ")
            strCommands += "delete policy-options prefix-list wazuh.blacklist {}\n".format(tmpWords[-1])
        strCommands += "set policy-options prefix-list wazuh.whitelist {}\n".format(ipaddress)
    else: #remove
        if not bPresent:
            strMsg += "The address {} is not in wazuh.blacklist nor wazuh.whitelist\n".format(ipaddress)
        elif bInBlacklist:
            strCommands="delete policy-options prefix-list wazuh.blacklist {}\n".format(ipaddress)
        elif bInWhitelist:
            strCommands+="delete policy-options prefix-list wazuh.whitelist {}\n".format(ipaddress)
        else:
            strMsg += "The address {} is not in wazuh.blacklist nor wazuh.whitelist\n".format(ipaddress)
    return strCommands, strMsg

def main():
    """main function
    will parse command line arguments, then dispatch to the related function
    """
    global bTrace
    bTrace = False
    parser = argparse.ArgumentParser(description="\
Interact with JunOS wazuh.blacklist applied to Ingress interface|n \
There must be 2 existing policy-options prefix-lists named:|n \
    wazuh.blacklist|n \
    wazuh.whitelist|n \
sample config should look like:|n \
    set interfaces <ingress interface> unit X family inet filter input wazuh.blacklist|n \
    set firewall family inet filter wazuh.blacklist term 10 from prefix-list wazuh.blacklist|n \
    set firewall family inet filter wazuh.blacklist term 10 from prefix-list wazuh.whitelist except|n \
    set firewall family inet filter wazuh.blacklist term 10 then discard|n \
    set firewall family inet filter wazuh.blacklist term 999 then accept|n \
    set policy-options prefix-list wazuh.blacklist 192.0.2.0/24|n \
    set policy-options prefix-list wazuh.whitelist fe80::/10|n \
        ", formatter_class=MultilineFormatter)
    parser.add_argument("-H", "--host", type=str, help="hostname or IP address of JunOS appliance.", required= True)
    parser.add_argument("-u", "--username", type=str, help="username to logon", required=True)
    parser.add_argument("-k", "--keyfile", type=str, help="private key file path", required=True)
    parser.add_argument("-p", "--passphrase", type=str, help="keyfile passphrase", required=True)
    parser.add_argument("-i", "--ipaddress", type=str, help="IP address to block/unblock, whitelist/unwhitelist", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-b", "--ban", action="store_true", help="ban the IP address - add it to wazuh.blacklist")
    group.add_argument("-w", "--whitelist", action="store_true", help="whitelist the IP address - add it to wazuh.whitelist")
    group.add_argument("-r", "--remove", action="store_true", help="remove the IP address from blacklist and whitelist")
    ##group.add_argument("-I", "--init", type=str, default="", help="Initialize configuration with default settings.| Parameter is the interface on which to apply the input filter (caution, erase existing filter). blacklist=192.0.2.0/24, whitelist=fe80::/10")
    group.add_argument("-I", "--init", type=str, default="", help=argparse.SUPPRESS)
    parser.add_argument("-d", "--dryrun", action="store_true", help="show commands that will be executed, but without executing them")
    parser.add_argument("-t", "--trace", action="store_true", help="debug mode")

    args = parser.parse_args()
    
    host = args.host
    username = args.username
    keyfile = args.keyfile
    passphrase = args.passphrase
    ipaddress = args.ipaddress
    bTrace = args.trace
    try:
        device= {
            "device_type": "juniper_junos",
            "host": host,
            "username": username,
            "use_keys": True,
            "key_file": keyfile,
            "passphrase": passphrase,
        }
        tmpconn = Netmiko(**device)
    except:
        if bTrace:
            print ("Error connecting to host {} with username {} and keyfile {}".format(host, username, keyfile))
        sys.exit(1)
    prompt = tmpconn.find_prompt()
    if bTrace:
        print(prompt)
    commands, strMsg = getcommands(ipaddress, args.ban, args.whitelist, args.remove, args.init, tmpconn)
    if commands != "":
        commands += "commit and-quit\n"
        if bTrace:
            print()
        if not args.dryrun:
            output = tmpconn.send_config_set(commands)
            strMsg += output + "\n"
        else:
            strMsg += "*** Dry Run Mode, those commands won't be applied ***\n"
            strMsg += commands
    else:
        strMsg += "Nothing to do with {}".format(ipaddress)

    if bTrace:
        print(strMsg)
    tmpconn.disconnect()

if __name__ == "__main__":
    main()
