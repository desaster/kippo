#!/usr/bin/env python

import os, pickle, sys, locale, getopt
from stat import *

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, \
    A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(0, 10)
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(0, 7)
PROC = False
VERBOSE = False

def logit(ftxt):
    if VERBOSE:
        sys.stderr.write(ftxt)

def recurse(localroot, root, tree, maxdepth = sys.maxint):
    if maxdepth == 0: return

    localpath = os.path.join(localroot, root[1:])

    logit(' %s\n' % (localpath))

    if not os.access(localpath, os.R_OK):
       logit(' Cannot access %s\n' % localpath)
       return

    for name in os.listdir(localpath):
        fspath = os.path.join(root, name)
        if fspath in (
                '/root/fs.pickle',
                '/root/createfs.py',
                '/root/.bash_history',
                ):
            continue

        path = os.path.join(localpath, name)

        try:
            if os.path.islink(path):
                s = os.lstat(path)
            else:
                s = os.stat(path)
        except OSError:
            continue

        entry = [name, T_FILE, s.st_uid, s.st_gid, s.st_size, s.st_mode, \
            int(s.st_mtime), [], None, None]

        if S_ISLNK(s[ST_MODE]):
            if not os.access(path, os.R_OK):
                logit(' Cannot access link: %s\n' % path)
                continue
            realpath = os.path.realpath(path)
            if not realpath.startswith(localroot):
                logit(' Link "%s" has real path "%s" outside local root "%s"\n' \
                    % (path, realpath, localroot))
                continue
            else:
                entry[A_TYPE] = T_LINK
                entry[A_TARGET] = realpath[len(localroot):]
        elif S_ISDIR(s[ST_MODE]):
            entry[A_TYPE] = T_DIR
            if  (PROC or not localpath.startswith('/proc/')) and maxdepth > 0:
                recurse(localroot, fspath, entry[A_CONTENTS], maxdepth - 1)
        elif S_ISREG(s[ST_MODE]):
            entry[A_TYPE] = T_FILE
        elif S_ISBLK(s[ST_MODE]):
            entry[A_TYPE] = T_BLK
        elif S_ISCHR(s[ST_MODE]):
            entry[A_TYPE] = T_CHR
        elif S_ISSOCK(s[ST_MODE]):
            entry[A_TYPE] = T_SOCK
        elif S_ISFIFO(s[ST_MODE]):
            entry[A_TYPE] = T_FIFO
        else:
            sys.stderr.write('We should handle %s' % path)
            sys.exit(1)

        tree.append(entry)

def help(brief = False):
    print 'Usage: %s [-h] [-v] [-p] [-l dir] [-d maxdepth] [-o file]\n' % \
        os.path.basename(sys.argv[0])

    if not brief:
        print '  -v             verbose'
        print '  -p             include /proc'
        print '  -l <dir>       local root directory (default is current working directory)'
        print '  -d <depth>     maximum depth (default is full depth)'
        print '  -o <file>      write output to file instead of stdout'
        print '  -h             display this help\n'

    sys.exit(1)

if __name__ == '__main__':
    maxdepth = sys.maxint
    localroot = os.getcwd()
    output = ''

    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'hvpl:d:o:', ['help'])
    except getopt.GetoptError, error:
        sys.stderr.write('Error: %s\n' % error)
        help()

    for o, a in optlist:
        if   o == '-v': VERBOSE = True
        elif o == '-p': PROC = True
        elif o == '-l': localroot = a
        elif o == '-d': maxdepth = int(a)
        elif o == '-o': output = a
        elif o in ['-h', '--help']: help()

    if output and os.path.isfile(output):
        sys.stderr.write('File: %s exists!\n' % output)
        sys.exit(1)

    logit('Processing:\n')

    tree = ['/', T_DIR, 0, 0, 0, 0, 0, [], '']
    recurse(localroot, '/', tree[A_CONTENTS], maxdepth)

    if output:
        pickle.dump(tree, open(output, 'wb'))
    else:
        print pickle.dumps(tree)

