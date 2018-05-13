#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__version__ = "0.0.6.5"

import configparser as cp
import optparse as op
import re
import os
import sys
import json
import subprocess

import stem
from stem.control import Controller

# Usage:
#
# Make a new directory. cd to the directory and populate it with
# a configuration file repo.cfg listing some peers.
#
# Initialize:
#  Either a) new (git init repo/) ->
#    $ python Globalist.py -i
#  or     b) from existing (torsocks git clone git://example7abcdefgh.onion) ->
#    $ python Globalist.py -c
#
# Have fun:
#  Run server
#    $ python Globalist.py
#  Pull from peers once
#    $ python Globalist.py -p
#  Periodically pull, don't serve
#    $ python Globalist.py -pP 1800
#  Periodically pull and also serve
#    $ python Globalist.py -P 1800
#
# That's it. Note that you can manage the repo.git/ and repo.cfg separately.

# One can simply check in a list of onions for open peering
# as PEERS.txt ...

# Anyone can commit anything and there's no mechanism for permanently
# blacklisting malicious peers (although one can simply remove them
# as they crop up and refuse to accept their commits).

# [network]
# peers = example7abcdefgh.onion, example8abcdefgh.onion
# (possibly prefixed with somebody:authkey@ ...)

# when using -b (bare), merge remote changes locally after
# git pull origin remote/origin/master.

DEFAULT_CONTROLPORT = 9151

STATUS = {'peers': None, 'socksport': None}

OPTIONS = None

class color:
    RED = '\x1b[31m'
    GOLD = '\x1b[33m'
    BOLD = '\x1b[1m'
    UNSET = '\x1b[0m'
    def red(s):
        return color.RED + s + color.UNSET
    def gold(s):
        return color.GOLD + s + color.UNSET
    def bold(s):
        return color.BOLD + s + color.UNSET

def git(command):
    return subprocess.Popen(["git"] + command)

def make_exportable(path):
    subprocess.Popen(["touch", os.path.abspath(os.path.join(path, "git-daemon-export-ok")) ]).wait()

def run_server(config, localport = 9418):
    hostname = config.get('onion', 'hostname')
    print ("Running git server on %s.onion" % hostname)

    peerstr = hostname + '.onion'

    try:
        authkey = config.get('onion', 'clientauth')
        if authkey:
            print ("Client auth is %s" % authkey)
            peerstr = '%s@%s.onion' % (authkey, hostname)
    except (KeyError, cp.NoOptionError) as e:
        print ("No client authentication required, repo will be public.")

    print ("Git server local port is %d" % localport)
    print ("You can now hand out the onion %s to prospective peers." % color.bold(peerstr))
    print ("It will be re-used anytime Globalist starts in this directory.")

    where = os.path.join(OPTIONS.o_dir, "repo")

    if OPTIONS.o_bare:
        where += ".git"
        make_exportable(where)
    else:
        make_exportable(os.path.join(where, ".git"))

    gitdaemon = git(["daemon", "--base-path=%s" % os.path.abspath(OPTIONS.o_dir),
                     "--reuseaddr", "--verbose",
                     "--disable=receive-pack",
                     "--listen=127.0.0.1", "--port=%d" % localport,
                     os.path.abspath(where)])
    output = gitdaemon.communicate()[0]
    print (output)

def makeonion(controller, config, options):

    try:
        controller.authenticate()
    except Exception as e:
        print ("Error: %s" % e)

    onion = None

    extra_kwargs = {}
    
    if config.has_section('onion'):
        print ("Attempting to use saved onion identity.")
        (keytype,key) = config.get('onion', 'key').split(':',1)

        if options.o_auth:
            try:
                print ("Attempting to use saved clientauth.")
                extra_kwargs['basic_auth'] =\
                dict([config.get('onion', 'clientauth').split(':',1)])
            except (KeyError, cp.NoOptionError) as e:
                print ("No client auth key found, generating one")
                extra_kwargs['basic_auth'] = {'somebody': None}
        else:
            try:
                extra_kwargs['basic_auth'] =\
                dict([config.get('onion', 'clientauth').split(':',1)])
                print ("Client auth key found, using it.")
            except (KeyError, cp.NoOptionError) as e:
                print ("Not using client auth.")

        if options.o_ap:
            print ("Waiting for onion to be published.")

        onion = controller.create_ephemeral_hidden_service(**extra_kwargs, ports={9418: options.a_localport}, discard_key=True, await_publication=options.o_ap, key_type=keytype, key_content=key)

    else:
        print ("I'm afraid we don't have an identity yet, creating one.")

        if options.o_auth:
            extra_kwargs['basic_auth'] = {'somebody': None}

        if options.o_ap:
            print ("Waiting for onion to be published.")

        onion = controller.create_ephemeral_hidden_service(**extra_kwargs, ports={9418: options.a_localport}, discard_key=False, await_publication=options.o_ap)

    print ("Onion OK.")

    if not onion.is_ok():
        raise Exception('Failed to publish onion.')
    else:

        # perhaps avoid overwriting when already present?
        for line in onion:

            if line != "OK":
                k, v = line.split('=', 1)

                # Request the key only if the service is new:
                if k == "PrivateKey":
                    try:
                        config.add_section('onion')
                    except cp.DuplicateSectionError as e:
                        pass
                    config.set('onion', 'key', v)
                if k == "ServiceID":
                    try:
                        config.add_section('onion')
                    except cp.DuplicateSectionError as e:
                        pass
                    config.set('onion', 'hostname', v)
                if k == "ClientAuth":
                    try:
                        config.add_section('onion')
                    except cp.DuplicateSectionError as e:
                        pass
                    config.set('onion', 'clientauth', v)
            config.write(open(os.path.join(OPTIONS.o_dir, 'repo.cfg'), 'w'))


def set_client_authentications(ls):
    global OPTIONS
    options = OPTIONS

    controller = Controller.from_port(port = options.a_controlport)
    controller.authenticate()
    # is there no sane way to _append_ a multi-config option in Tor????
    controller.set_caching(False)

# except it doesn't work, the 650 message never arrives. why?
#    controller.add_event_listener(my_confchanged_listener, EventType.CONF_CHANGED)
# SETEVENTS conf_changed

    hsa = controller.get_conf_map('hidservauth') 

    for authpair in ls:
        if authpair['auth'] and len(authpair['auth']):
            hsa['hidservauth'].append('%s.onion %s' % (authpair['onion'], authpair['auth']))

    hsa['hidservauth'] = list(set(hsa['hidservauth']))

    controller.set_conf('hidservauth', hsa['hidservauth'])
    controller.close()
    

def getpeers(config):
    if STATUS['peers']:
        return STATUS['peers']

    if config.has_section('network'):
        peerslist = config.get('network', 'peers').split(',')
        peers = []
        authpairs = []

        for peerentry in peerslist:

            # extract what looks like an onion identifier
            try:
                authpair = re.findall('(?:(somebody:[A-Za-z0-9+/]{22})@)?([a-z2-8]{16})', peerentry)[0]

                userpass = authpair[0].split(":",1)
                if not userpass or not len(userpass)==2:
                    userpass = (None, None)

                authpairs += [{'auth':userpass[1],
                               'user':userpass[0], # somebody
                               'onion':authpair[1]}]
                peers += [authpair[1]]

            except Exception as e:
                print (e)

        set_client_authentications(authpairs)

        STATUS['peers'] = peers

        return peers

    else:
        STATUS['peers'] = []

        return []

def clone(config):
    peers = getpeers(config)

    # FIXME: when the first fails, we should move on to the next..

    theonion = peers[0]

    what  = "git://%s.onion/repo" % theonion
    where = os.path.join(OPTIONS.o_dir, "repo")
    how   = []

    if OPTIONS.o_bare:
        what  += ".git"
        where += ".git"
        how   = ["--bare", "--mirror"]

    cloneproc = subprocess.Popen(["torsocks", "-P", STATUS['socksport'], "git", "clone"] + how + [what, where])
    if cloneproc.wait() != 0:
        print ("Error cloning, exiting.")
        return -1
    else:
        make_exportable(where)

    print("Adding remote mirror %s" % theonion)
    proc_setMirror = subprocess.Popen(["torsocks", "-P", STATUS['socksport'], "git", "-C", os.path.abspath(where), "remote", "add", "--mirror=fetch", theonion, what])
    proc_setMirror.wait()

    # Make a local editable repo
    if OPTIONS.o_bare:
        git(["clone", os.path.join(OPTIONS.o_dir, "repo.git"),
                      os.path.join(OPTIONS.o_dir, "repo")]).wait()

def pull(config):
    peers = getpeers(config)

    print ("Pulling from %s" % peers)

    processes = []
    for peer in peers:
        what  = "git://%s.onion/repo.git" % peer

        print("Adding remote mirror %s" % peer)
        proc_setMirror = subprocess.Popen(["torsocks", "-P", STATUS['socksport'], "git", "-C", os.path.abspath(os.path.join(OPTIONS.o_dir, "repo")), "remote", "add", "--mirror=fetch", peer, what])
        proc_setMirror.wait()

        processes.append([peer, subprocess.Popen(["torsocks", "-P", STATUS['socksport'], "git", "-C", os.path.abspath(os.path.join(OPTIONS.o_dir, "repo")), "pull", "git://%s.onion/repo" % peer])])
        
    for (peer,proc) in processes:
        if proc.wait() != 0:
            print ("Error with %s" % peer)

def fetch(config):
    peers = getpeers(config)
    print ("Fetching from %s" % peers)
    processes = []
    for peer in peers:

        what  = "git://%s.onion/repo.git" % peer

        print("Adding remote mirror %s" % peer)
        proc_setMirror = subprocess.Popen(["torsocks", "-P", STATUS['socksport'], "git", "-C", os.path.abspath(os.path.join(OPTIONS.o_dir, "repo.git")), "remote", "add", "--mirror=fetch", peer, what])
        proc_setMirror.wait()

        processes.append([peer, subprocess.Popen(["torsocks", "-P", STATUS['socksport'], "git", "-C", os.path.abspath(os.path.join(OPTIONS.o_dir, "repo.git")), "fetch", peer])])
# +refs/heads/*:refs/remotes/origin/*'])])

    for (peer,proc) in processes:
        if proc.wait() != 0:
            print ("Error with %s" % peer)

def init(config):
    print ("Initializing ...")

    if OPTIONS.o_bare:
        git(["init", os.path.join(OPTIONS.o_dir, "repo.git"), "--bare"]).wait()
        # Make a local editable repo:
        git(["clone", os.path.join(OPTIONS.o_dir, "repo.git"), os.path.join(OPTIONS.o_dir, "repo")]).wait()

    else:
        git(["init", os.path.join(OPTIONS.o_dir,"repo")]).wait()

    print ("Initialized")

def main(args=[]):
    # OptionParser is capable of printing a helpscreen
    opt = op.OptionParser()

    opt.add_option("-V", "--version", dest="o_version", action="store_true",
                   default=False, help="print version number")

    opt.add_option("-i", "--init", dest="o_init", action="store_true",
                   default=False, help="make new empty repo")

    opt.add_option("-b", "--bare", dest="o_bare", action="store_true",
                   default=False, help="use bare repos and fetch, not pull (recommended)")

    opt.add_option("-c", "--clone", dest="o_clone", action="store_true",
                   default=False, help="clone repo from 1st peer")

    opt.add_option("-p", "--pull", dest="o_pull", action="store_true",
                   default=False, help="pull / fetch from peers and don't serve")

    opt.add_option("-P", "--periodically-pull", dest="a_pull", action="store",
                   type="int", default=None, metavar="PERIOD",
                   help="pull / fetch from peers every n seconds")

    opt.add_option("-L", "--local", dest="a_localport", action="store", type="int",
                   default=9418, metavar="PORT", help="local port for git daemon")

    opt.add_option("-C", "--control-port", dest="a_controlport", action="store", type="int",
                   default=9151,  metavar="PORT", help="Tor controlport")

    opt.add_option("-a", "--await", dest="o_ap", action="store_true",
                   default=False, help="await publication of .onion in DHT before proceeding")

    opt.add_option("-x", "--auth", action="store_true", default=False,
                   dest="o_auth", help="enable authentication (private)")

    opt.add_option('-d', "--dir", dest="o_dir", action="store", type="string", default=".", metavar="DIR", help="base directory")

    (options, args) = opt.parse_args(args)

    global OPTIONS
    OPTIONS = options

    print(color.gold('This is Globalist V%s') % __version__)

    if options.o_version:
        print (__version__)
        return 0

    if options.o_auth and stem.__version__ < '1.5.0':
        sys.stderr.write ("Error: stem version >=1.5.0 required for auth\n")
        return 1

    if not options.a_controlport:
        options.a_controlport = DEFAULT_CONTROLPORT

    if not os.path.isdir(options.o_dir):
        sys.stderr.write ("Error: directory %s does not exist\n" % options.o_dir)
        return 1

    # Extract socksport via c.get_conf and use this (-P in torsocks)
    controller = Controller.from_port(port = options.a_controlport)
    controller.authenticate()
    try:
        STATUS['socksport'] = controller.get_conf('SocksPort').split(" ",1)[0]
    except AttributeError as e:
        print("Error: tor controller present at %d but SocksPort not set." % options.a_controlport)
        return 1
    controller.close()

    config = cp.ConfigParser()
    cfgfile = None
    try:
        cfgfile = open(os.path.join(options.o_dir, 'repo.cfg'), "r")
    except FileNotFoundError as e:
        print("Trying to make file repo.cfg")
        try:
            os.mknod(os.path.join(options.o_dir, 'repo.cfg'))
            os.chmod(os.path.join(options.o_dir, 'repo.cfg'), 0o600)
            cfgfile = open(os.path.join(options.o_dir, 'repo.cfg'))
        except Exception as e:
            print (e)
            return 1

    config.readfp(cfgfile)

    try:
        os.stat(os.path.join(options.o_dir, "repo.git"))
        if not options.o_bare:
            print ("repo.git exists, setting -b implicitly")
            # TODO -B to override
        options.o_bare = True

    except FileNotFoundError as e:
        if not options.o_init and not options.o_clone and options.o_bare:
            print ("./repo.git/ does not exist, try -ib or -cb")
            return 1

    try:
        os.stat(os.path.join(options.o_dir, "repo"))

    except FileNotFoundError as e:
        if not options.o_init and not options.o_clone and not options.o_bare:
            print("./repo/ does not exist, try -i or -c")
            return 1

    except Exception as e:
        print (e)
        return 1

    if options.o_init:
        init(config)

    peers = getpeers(config)

    if options.o_clone:
        if not len(peers):
            print ("No peers, can't clone. Please enter a peer in repo.cfg")
        clone(config)
        return 1

    threads = []

    if options.a_pull:
        if not len(peers):
            print ("No peers, not starting pulling task.")

        else:
            import threading
            from   datetime import timedelta as td
            from   datetime import datetime
            
            class T:
                def __init__(self):
                    self.last = datetime.now()
                    
                def run(self):
                    if options.o_bare:
                        fetch(config)
                    else:
                        pull(config)
                    threading.Timer(options.a_pull, T.run, args=(self,)).start()
                    
            task = T()

            t = threading.Thread(target=T.run, args=(task,))
            t . setDaemon(True)
            threads.append(t)
            t.start()

    if options.o_pull and not options.a_pull:
        if options.o_bare:
            fetch(config)
        else:
            pull(config)

    elif not options.o_pull:
        controller = Controller.from_port(port = options.a_controlport)
        makeonion(controller, config, options)
        run_server(config, localport = options.a_localport)
        controller.close()

    for t in threads:
        t.join()
