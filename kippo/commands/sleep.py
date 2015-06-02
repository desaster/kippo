
from twisted.internet import reactor

from kippo.core.honeypot import HoneyPotCommand

commands = {}

'''sleep'''
class command_sleep(HoneyPotCommand):
    def done(self):
        self.exit()

    def start(self):
        if len(self.args) == 1:
            _time = int( self.args[0] )
            self.scheduled = reactor.callLater(_time, self.done)
        else:
            self.writeln('usage: sleep seconds') 
            self.exit()


commands['/bin/sleep'] = command_sleep

# vim: set sw=4 et tw=0:
