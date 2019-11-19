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
rxThread = None
reattemptByParseError = 3
reattemptByError = 3
bShowOutput = False
muxServer = None
muxSession = None
muxWindow = None
rxString = ""
oldStrPos = 0


# Signal Handler, stop_program and exit safely
"""
    OS signal handle
"""
def signal_handler(signum=None, frame=None):
    global bShutdown
    bShutdown = True

def printHelp():
    print("help: ")
    print("    python3 test_cli_cmd.py <cli_cmd> <proof_in_answer> <tmux_session_name (-s)> (outputCli)")
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
    clear buffered out of tmux session
"""
def clearTMuxOut():
    global muxWindow
    global bDebugOutput
#    global rxString
#    global oldStrPos

#    rxAll = ""

    if muxWindow is not None:
        pass
#        rxAll = str(muxWindow.cmd('capture-pane', '-p').stdout)
#        muxWindow.reset() // NOT WORK -> CLEAR SENDS an reset to CLI!
#        muxWindow.clear()

#    oldStrPos = len(rxAll)

#    if bDebugOutput is True:
#        print("\n\nclearTMuxOut > rxAll: \n" + str(rxAll))
#        print("\n\nclearTMuxOut > Pos: \n" + str(oldStrPos))
#    if muxWindow is not None:
#        muxWindow.clear()

"""
    send a cmd to the posix program
"""
def sendCliCmd(aCmd):
    global muxWindow
    if muxWindow is not None:
        muxWindow.send_keys(str(aCmd))

"""
    get new output from window
"""
def readPosixOut():
    global rxString
    global muxWindow
#    global oldStrPos

#    time.sleep(2)
    if muxWindow is not None:
        rxString += str(muxWindow.cmd('capture-pane', '-p').stdout)
#        rxString += rxNow[oldStrPos:]
        clearTMuxOut()

    if bDebugOutput is True:
#        print("\n\nread > all: \n" + str(rxNow))
#        print("\n\nread > pos: \n" + str(oldStrPos))
        print("\n\nread > final rx string: \n" + str(rxString))

def findOutputSinceLatestCmd(mCmd):
    global rxString

    return str(rxString[rxString.rfind(str(mCmd)):])

"""
    MAIN Routine
    Starts all Processes
"""
def main(argv):
    global bShutdown
    global rxThread
    global reattemptByParseError
    global reattemptByError
    global bShowOutput
    global muxWindow

    exitCode = 1
    bShutdown = False

    # add signal handel for exit signals
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
        signal.signal(sig, signal_handler)

    print("POSIX CLI Test")

    # ckeck param
    if(len(argv) < 4):
        printHelp()
        exit(1)

    # check for output bool
    if(len(argv) >= 5):
        if("true" in argv[4]):
            print("Print CLI Output: true")
            bShowOutput = True

    # start test

    # open session
    getWindow(str(argv[3]))
    if muxWindow is None:
        exit(1)

    clearTMuxOut()
#    time.sleep(1)

    parseError = True
    Error = True

    parseErrorCnt = 0
    errorCnt = 0

    while(parseErrorCnt < reattemptByParseError and (parseError or Error) and errorCnt < reattemptByError and not bShutdown):

        exitCode = 0

        try:
            if parseError is True:
                sendCliCmd(str(argv[1]))
        except Exception as e:
            exitCode = 1
            print("cant write to posix device: " + argv[1])
            print("Error: " + e)
            errorCnt += 1
            Error = True
            parseError = False

        try:
            time.sleep(1)
            readPosixOut()
        except Exception as e:
            print("Cant read answer: " + e)
            errorCnt += 1
            parseError = False
            Error = True
            exitCode = 1

        if (exitCode is 0):

            if(bShowOutput):
                print("\nCLI Output (latest CMD): \n" + str(findOutputSinceLatestCmd(argv[1])) +"\n")

            # proof result
            if argv[2] in findOutputSinceLatestCmd(argv[1]):
                exitCode = 0
                print("CLI Test Done: PASS")
                parseError = False
                Error = False
            elif "Error 6" in findOutputSinceLatestCmd(argv[1]):
                parseError = True
                Error = False
                parseErrorCnt += 1
                exitCode = 1
                if bShowOutput is True:
                    print("CLI Test: Parse Error > Resend")
                time.sleep(1)
            elif "Error 24: Already" in findOutputSinceLatestCmd(argv[1]):
                if (bShowOutput):
                    print("\nCLI Returns Already.\n")
                    print("\nNOTE: >> >> Accept it as **~XFAIL~** << <<\n")
                parseError = False
                Error = False
            elif "Error" in findOutputSinceLatestCmd(argv[1]):
                parseError = False
                Error = True
                errorCnt += 1
                exitCode = 1
                if bShowOutput is True:
                    print("CLI Test: Parse Error > Resend")
            else:
                print("CLI Test: Response not received. Wait...")
                # for follow cmd's its necessary to resend the cmd
                if ("state" in argv[1]):
                    parseError = True
                else:
                    parseError = False
                Error = True
                time.sleep(10 + 20*parseErrorCnt)
                parseErrorCnt += 1
                exitCode = 1

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
