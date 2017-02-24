#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Globalist: manage a global repo via decentral git instances
# you may peer with any number of other Globalist onions

# Think onionshare, but with permanent onion addresses, P2P and DVCS

# Python2/3. Dependencies:
#   - stem (torsocks pip install stem / via distro)

#   - git must be installed
#   - torsocks must be installed
#   - tor must be up and running and the ControlPort open

# Use scenario:
# a) Run Tor.
# b) Run the server in the background and schedule a job for pulling from peers.
#    it is a git server that listens on <your-identifier>.onion:9418
# c) Globalist.py creates a git, which you may use to push and pull your own changes.

__version__ = "0.0.2"

try:
    import ConfigParser as cp
except:
    import configparser as cp # python3
import optparse as op
import re
import os
import sys
import subprocess



from stem.control import Controller

# Usage:
#
# Make a directory.
#
# Put a configuration file repo.cfg listing some peers. Done.
#
# Initialize:
#  Either a) git init repo/
#    $ python Globalist.py -i
#  or     b) torsocks git clone git://example7abcdefgh.onion
#    $ python Globalist.py -c
#
# Have fun:
#  Run server
#    $ python Globalist.py
#  Pull from peers
#    $ python Globalist.py -p
#
# That's it.

# One can simply check in a list of onions for open peering
# as PEERS.txt ...

# A word of CAUTION: anyone can commit anything
# and there's no mechanism for permanently blacklisting
# malicious peers (although one can simply remove them
# as they crop up and roll back their changes).
#
# A future version of Globalist.py should introduce
# signed commits + reputation system, when the need arises.

# [network]
# peers = example7abcdefgh.onion, example8abcdefgh.onion

DEFAULT_CONTROLPORT = 9151

def run_server(config, localport = 9418):
    print ("Running git server on %s:9418" % config.get('onion', 'hostname'))
    print ("You can now hand out this onion to prospective peers.")
    print ("It will be re-used anytime Globalist starts in this directory.")
    subprocess.Popen(["touch",  os.path.abspath(os.path.join("repo",".git","git-daemon-export-ok")) ]).wait()
    gitdaemon = subprocess.Popen(["git", "daemon", "--base-path=%s" % os.path.abspath("."),
                                  "--reuseaddr", "--verbose",
    # there could be a global setting enabling write access??
                                  "--disable=receive-pack",
                                  "--listen=127.0.0.1", "--port=%d" % localport,
                                  os.path.abspath("repo")])
    output = gitdaemon.communicate()[0]
    print (output)
    # then background this process

def makeonion(controller, config, options):
    # stem docs say: provide the password here if you set one:
    controller.authenticate()
    
    onion = None

    if config.has_section('onion'):
        print ("Attempting to use saved onion identity")
        (keytype,key) = config.get('onion', 'key').split(':',1)
        onion = controller.create_ephemeral_hidden_service(ports={9418: options.a_localport}, discard_key=True, await_publication=options.o_ap, key_type=keytype, key_content=key)
    else:
        print ("I'm afraid we don't have an identity yet, creating one")
        onion = controller.create_ephemeral_hidden_service(ports={9418: options.a_localport}, discard_key=False, await_publication=options.o_ap)

    # print onion
    print ("Tor controller says Onion OK")

    if not onion.is_ok():
        raise Exception('Failed to publish onion.')
    else:
        for o in onion:
            if o != "OK":
                k, v = o.split('=', 1)
                # we only request the key if the service is new
                if k == "PrivateKey":
                    try:
                        config.add_section('onion')
                    except cp.DuplicateSectionError as e:
                        pass
                    config.set('onion', 'key', v)
                    config.write(open('repo.cfg', 'w'))
                if k == "ServiceID":
                    try:
                        config.add_section('onion')
                    except cp.DuplicateSectionError as e:
                        pass
                    config.set('onion', 'hostname', v)
                    config.write(open('repo.cfg', 'w'))

def getpeers(config):
    if config.has_section('network'):
        peerslist = config.get('network', 'peers').split(',')
        peers = []
        for peerdomain in peerslist:
            # extract what looks like an onion identifier
            try:
                peerdomain = re.findall('[a-z2-8]{16}', peerdomain)[0]
                print ("Given %s" % peerdomain)
                peers += [peerdomain]
            except Exception as e:
                print (e)
        return peers
    else:
        return []

def clone(config):
    peers = getpeers(config)

    # FIXME: when the first fails, we should move on to the next..
    cloneproc = subprocess.Popen(["torsocks", "git", "clone", "git://%s.onion/repo" % peers[0], "repo"])
    if cloneproc.wait() != 0:
        print ("Error cloning, exiting.")
        exit(-1)
    else:
        subprocess.Popen(["touch",  os.path.abspath(os.path.join("repo",".git","git-daemon-export-ok")) ]).wait()

    processes = []
    for peer in peers[1:]:
        processes.append([peer, subprocess.Popen(["torsocks", "git", "-C", os.path.abspath("repo"), "pull", "git://%s.onion/repo" % peer])])
        
    for (peer,proc) in processes:
        if proc.wait() != 0:
            print ("Error with %s" % peer)

def pull(config):
    peers = getpeers(config)

    processes = []
    for peer in peers:
        processes.append([peer, subprocess.Popen(["torsocks", "git", "-C", os.path.abspath("repo"), "pull", "git://%s.onion/repo" % peer])])
        
    for (peer,proc) in processes:
        if proc.wait() != 0:
            print ("Error with %s" % peer)

def init(config):
    print ("Initializing ...")
    p = subprocess.Popen(["git", "init", "repo"])
    p.wait()
    print ("Initialized")

if __name__=='__main__':
    # default settings

    opt = op.OptionParser()
    opt.add_option("-i", "--init", dest="o_init", action="store_true",
                   default=False, help="make new empty repo")
    opt.add_option("-c", "--clone", dest="o_clone", action="store_true",
                   default=False, help="clone repo from 1st peer")
    opt.add_option("-p", "--pull", dest="o_pull", action="store_true",
                   default=False, help="pull from peers")
    opt.add_option("-L", "--local", dest="a_localport", action="store", type="int",
                   default=9418, help="local port for git daemon")
    opt.add_option("-P", "--control-port", dest="a_controlport", action="store", type="int",
                   default=9418, help="Tor controlport")
    opt.add_option("-a", "--await", dest="o_ap", action="store_true",
                   default=False, help="await publication of .onion in DHT before proceeding")
    (options, args) = opt.parse_args()

    if not options.a_controlport:
        options.a_controlport = DEFAULT_CONTROLPORT

    config = cp.ConfigParser()
    cfgfile = None
    try:
        cfgfile = open('repo.cfg')
    except FileNotFoundError as e:
        print("Trying to make file repo.cfg")
        try:
            os.mknod("repo.cfg")
            os.chmod("repo.cfg", 0o600)
            cfgfile = open('repo.cfg')
        except Exception as e:
            print (e)
            exit(1)

    config.readfp(cfgfile)

    # print options

    try:
        os.stat("repo")
    except FileNotFoundError as e:
        if not options.o_init:
            print("./repo/ does not exist, try %s -i" % sys.argv[0])
            exit(1)
    except Exception as e:
        print (e)
        exit(1)

    if options.o_init:
        init(config)

    if options.o_clone:
        clone(config)
        exit(1)

    # It's either pull or serve. It's no problem running pull while the
    # server is up.
    if options.o_pull:
        pull(config)
    else:
        controller = Controller.from_port(port = options.a_controlport)
        makeonion(controller, config, options)
        run_server(config, localport = options.a_localport)
        controller.close()
