#!/usr/bin/env python

# twisted imports
from twisted.words.protocols import irc
from twisted.internet import reactor, protocol, task
from twisted.python import log

# system imports
import time, sys, string, os
from datetime import datetime as dt
from urlparse import urlparse

# interface imports
import k8055
import simplejson
import argparse
import oauth
from twittytwister import twitter

class MessageLogger:
    """
    An independent logger class (because separation of application
    and protocol logic is a good thing).
    """
    def __init__(self, file):
        self.file = file

    def log(self, message):
        """Write a message to the file."""
        timestamp = time.strftime("[%H:%M:%S]", time.localtime(time.time()))
        self.file.write('%s %s\n' % (timestamp, message))
        self.file.flush()

    def close(self):
        self.file.close()


class IRCBot(irc.IRCClient):
    """A logging IRC bot."""


    def connectionMade(self):
        irc.IRCClient.connectionMade(self)
        self.logger = MessageLogger(open(self.factory.filename, "a"))
        self.logger.log("[connected at %s]" %
                        time.asctime(time.localtime(time.time())))
        self.loopcall.start(10.0)

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        self.logger.log("[disconnected at %s]" %
                        time.asctime(time.localtime(time.time())))
        self.logger.close()

    # Custom functions

    def logged_msg(self,target,msg):
        self.msg(target,msg)
        self.logger.log("<%s> %s" % (target,msg))


    # callbacks for events

    def signedOn(self):
        """Called when bot has succesfully signed on to server."""
        self.join(self.factory.channel)
        self.msg("Nickserv", "identify %s"%self.password)

    def joined(self, channel):
        """This will get called when the bot joins the channel."""
        self.logger.log("[I have joined %s]" % channel)

    def privmsg(self, user, channel, msg):
        """This will get called when the bot receives a message."""
        user = user.split('!', 1)[0]
        self.logger.log("<%s> %s" % (user, msg))

        # Check to see if they're sending me a private message
        if channel == self.nickname:
            msg = "Hello, I'm the IRC bot for %s" % self.space.name
            self.logged_msg(user, msg)
            return

        # Check to see if they're asking me for help
        if msg == self.nickname + ": help":
            msg = "%s: I'm a little stupid at the minute; current commands I accept are:" % user
            self.logged_msg(channel, msg)
            msg = "%s: open" % self.nickname
            self.logged_msg(channel, msg)
            return

        # Check to see if the hackerspace is open
        if msg == self.nickname + ": open":
            msg = "%s: The space is %s" % ( user , self.space.status())
            self.logged_msg(channel, msg)

        # Otherwise check to see if it is a message directed at me
        if msg.startswith(self.nickname + ": tweet "):
            txt = "%s said: %s"%(user,string.join(msg.split()[2:]))
            if self.space.twitter:
                self.space.twitter.tweet(txt)
                self.logged_msg(channel, msg + ": successful")
            else:
                self.logged_msg(channel, msg + ": failed")

        # Otherwise check to see if it is a message directed at me
        if msg.startswith(self.nickname + ":"):
            msg = "%s: I am a log bot" % user
            msg += ", say \'%s:help\' for more information" % self.nickname
            self.logged_msg(channel, msg)
            return

    def action(self, user, channel, msg):
        """This will get called when the bot sees someone do an action."""
        user = user.split('!', 1)[0]
        self.logger.log("* %s %s" % (user, msg))

    # irc callbacks

    def irc_NICK(self, prefix, params):
        """Called when an IRC user changes their nickname."""
        old_nick = prefix.split('!')[0]
        new_nick = params[0]
        self.logger.log("%s is now known as %s" % (old_nick, new_nick))


    # For fun, override the method that determines how a nickname is changed on
    # collisions. The default method appends an underscore.
    def alterCollidedNick(self, nickname):
        """
        Generate an altered version of a nickname that caused a collision in an
        effort to create an unused related name for subsequent registration.
        """
        return nickname + '^'

    def heartbeat(self):
        """
        Periodically executed tasks
        """
        self.logger.log("launched heardbeat task")

        #if Space changed
        if self.space.state_changed():
            self.logged_msg(self.space.irc_chan,
                            "The space is now: %s" % self.space.status()
                            )
            self.logger.log("Button:%s,Config:%s" % ( 
                self.space.button_state(),
                self.space.state()
            ))



class IRCBotFactory(protocol.ClientFactory):
    """A factory for IRCBots.

    A new protocol instance will be created each time we connect to the server.
    """

    def __init__(self, space):
        self.channel = space.irc_chan
        self.filename = space.log_file
        self.space=space

    def buildProtocol(self, addr):
        p = IRCBot()
        p.factory = self
        p.space = self.space
        p.loopcall = task.LoopingCall(p.heartbeat)
        p.nickname = self.space.username
        p.password = self.space.password
        p.realname = self.space.name
        return p

    def clientConnectionLost(self, connector, reason):
        """If we get disconnected, reconnect to server."""
        connector.connect()

    def clientConnectionFailed(self, connector, reason):
        print "connection failed:", reason
        reactor.stop()

class twitterClient():
    """
    A Twitter Client
    """

    def __init__(self,auth,params):
        consumer = oauth.OAuthConsumer(auth['ckey'],auth['csecret'])
        token = oauth.OAuthToken(auth['akey'], auth['asecret'])

        self.client = twitter.Twitter(consumer=consumer, token=token)
        self.params = params

    def tweet(self,msg,params={}):
        params = dict(self.params.items() + params.items())
        self.client.update(msg,params)


class hackerspace():
    """
    Space Interface
    """
    def __init__(self,args):
        self.json_file = args.json_file
        self.password = args.pw

        self.config = simplejson.load(open(self.json_file,'r'))
        self.load_json_config(self.config)
        self.occupied = self.config['open']
        self.log_file = os.path.dirname(self.json_file)+self.username+".log"

        self._board = k8055.Board()
        self.client_init(args)

    def load_json_config(self,conf):
        try:
            self.name = conf['space']
            if 'botname' in conf:
                self.username = conf['botname']
            else:
                self.username = re.sub(r'\s','',self.name)
            irc = urlparse(conf['contact']['irc'])
            self.irc_net = irc.netloc
            self.irc_chan = string.strip(irc.path,'/#')
        except KeyError as err:
            log.err("Cannot Load Space Configuration: %s"%err)

    def client_init(self,args):
        # IRC
        self.irc_f = IRCBotFactory(self)
        reactor.connectTCP(self.irc_net,
                           6667,
                           self.irc_f)
        #Twitter
        if hasattr(args,'auth_file'):
            try:
                auth=simplejson.load(open(args.auth_file,'r'))
                self.twitter = twitterClient(args)
            except:
                log.err('Twitter could not be loaded')
                self.twitter = False
        else:
            log.err('No Credentials for twitter loaded')

    def button_state(self):
        self._board.read()
        return not self._board.digital_inputs[4]

    def state(self):
        return self.occupied

    def status(self):
        return "Open" if self.state() else "Closed"

    def update_json(self):
        self.config['open']=self.state()
        self.config['lastchange'] = dt.strftime(dt.utcnow(),"%s")
        self.config['status'] = self.status()
        simplejson.dump(self.config,
                        open(self.json_file,'w'),
                        indent=4,
                        sort_keys=True
                        )


    def update_twitter(self):
        if self.twitter:
            self.twitter.tweet("%s is now %s!" % (self.name, self.status))

    def state_changed(self):
        if self.state() != self.button_state():
            self.occupied = self.button_state()
            self.update_json()
            self.update_twitter()
            return True
        else:
            return False

    def run_if_changed(self,f):
        if self.state_changed():
            f(self.state())

if __name__ == '__main__':
    # initialize logging
    log.startLogging(sys.stdout)

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--tw_auth_file', dest='auth_file', action='store',
                        default=None,
                        help='Twitter Authentication File')
    parser.add_argument('--json_file', dest='json_file', action='store',
                        default=None,
                        help='Space definition file')
    parser.add_argument('--password', 
                        dest='pw', 
                        action='store',
                        default=None,
                        help='Super Secret Password')

    args = parser.parse_args()

    if (args.json_file is None):
        log.err("Need JSON file")
        sys.exit()
    
    if (args.pw is None):
        log.err("Need Password")
        sys.exit()

    print args
    #Create Hackerspace
    s=hackerspace(args)

    # run bot
    reactor.run()
