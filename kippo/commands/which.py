# Copyright (c) 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>
  
from kippo.core.honeypot import HoneyPotCommand
  
commands = {}
  
class command_which(HoneyPotCommand):
    # Do not resolve args
    resolve_args = False
  
    def call(self):
        """ Look up all the arguments on PATH and print each (first) result """
  
        # No arguments, just exit
        if not len(self.args) or not 'PATH' in self.env:
            return
  
        # Look up each file
        for f in self.args:
            for path in self.env['PATH'].split(':'):
                resolved = self.fs.resolve_path(f, path)
  
                if self.fs.exists(resolved):
                    self.writeln("%s/%s" % (path, f))
                    continue
  
# Definition
commands['/bin/which'] = command_which
