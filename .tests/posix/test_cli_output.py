#!/usr/bin/python3

# ############################################################################ #
#   _____       ______   ____
#  |_   _|     |  ____|/ ____|  Institute of Embedded Systems
#    | |  _ __ | |__  | (___    Wireless Group
#    | | | '_ \|  __|  \___ \   Zuercher Hochschule Winterthur
#   _| |_| | | | |____ ____) |  (University of Applied Sciences)
#  |_____|_| |_|______|_____/   8401 Winterthur, Switzerland
#
# ------------------------------------------------------------------------------
#
#  Copyright (c) 2018, Institute Of Embedded Systems at Zurich University
#  of Applied Sciences. All rights reserved.
#
#
#  THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#  SUCH DAMAGE.
#
# ------------------------------------------------------------------------------
#  File/Module:	    test_cli_cmd.py
#
#  Coding/ Indent:  utf8/ whitespace
#
#  Author:		    Christian Stauffer (stfc)
#
#  Date, Version:   26.09.2018, V 0.1
#
#  Description:     This Module send a cmd to OpenThread POSIX CLI which run
#                   in a tmux, check answer and return 0, if pass, otherwise 1.
#
#  Change Log:
#
# ############################################################################ #

# system modules import
import signal   # for exit signal
import sys      # for argv
import libtmux  # for interact with program running on a tmux
import time

bDebugOutput = False

# global vars
bShutdown = False
bShowOutput = False
muxServer = None
muxSession = None
muxWindow = None


# Signal Handler, stop_program and exit safely
"""
    OS signal handle
"""
def signal_handler(signum=None, frame=None):
    global bShutdown
    bShutdown = True

def printHelp():
    print("help: ")
    print("    python3 test_cli_output.py <proof_in_cli_out> <tmux_session_name (-s)> (outputCli)")
    print("        outputCli: optional, if cli output show, type 'true'")
    print("\n    Note: You must start the posix ot program first in a tmux.")
    print("\n           e.g. tmux new -d -s server-device output/x86_64-unknown-linux-gnu/bin/ot-cli-mtd 1")
    print("\n\n               -> session name in e.g. is: server-device")

"""
    search and get the session of posix program
"""
def getWindow(aSessionName):
    global bDebugOutput
    global muxServer
    global muxSession
    global muxWindow
    global bShowOutput

    muxServer = libtmux.Server()
    if muxServer is None:
        if bShowOutput is True:
            print("muxServer = None")
        return
    if bDebugOutput is True:
        print("TMUX-Server: " + str(muxServer))

    muxSession = muxServer.find_where({"session_name": str(aSessionName)})
    if muxSession is None:
        if bShowOutput is True:
            print("muxSession is None")
            print("  > make sure, you have started a 'tmux new -d -s " + str(aSessionName) + " ot_posix_program'. -> see help")
        return
    if bDebugOutput is True:
        print("TMUX-Session: " + str(muxSession))

    muxWindow = muxSession.attached_pane
    if muxWindow is None:
        if bShowOutput is True:
            print("muxWindow is None")
        return
    if bDebugOutput is True:
        print("TMUX-Window/Pane: " + str(muxWindow))

"""
    MAIN Routine
    Starts all Processes
"""
def main(argv):
    global bShowOutput
    global muxWindow

    exitCode = 1

    # add signal handel for exit signals
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
        signal.signal(sig, signal_handler)

    print("POSIX Test Output")

    # ckeck param
    if(len(argv) < 3):
        printHelp()
        exit(1)

    # check for output bool
    if(len(argv) >= 4):
        if("true" in argv[3]):
            print("Print CLI Output: true")
            bShowOutput = True

    # start test

    # open session
    getWindow(str(argv[2]))
    if muxWindow is None:
        exit(1)

    cliOutput = str(muxWindow.cmd('capture-pane', '-p').stdout)

    if(bShowOutput):
        print("\nCLI Output: \n" + cliOutput +"\n")

    # proof result
    if argv[1] in cliOutput:
        exitCode = 0
        print("CLI Test Done: PASS")

    # done
    if exitCode is 1:
        print("CLI Test Done: FAIL")

    sys.exit(exitCode)


# entry point of program
if __name__ == '__main__':
    if(len(sys.argv)>1):
        if("help" in sys.argv[1]):
            printHelp()
            exit(0)
    main(sys.argv)
