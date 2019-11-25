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
#                           Aurelio Schellenbaum (scnm)
#
#  Date, Version:   26.06.2018, V 0.1
#                               30.10.2019, V1.0
#
#  Description:     This Module send a cmd to OpenThread CLI and checks the
#                   Answer. Return 0 if passed, otherwise 1.
#
#  Change Log:
#
# ############################################################################ #

# system modules import
import signal   # for exit signal
import sys      # for argv
import serial   # for uart
import time # scnm

# global vars
bShutdown = False
serialUart = None
rxThread = None
reattemptByParseError = 3
reattemptByError = 3
bShowOutput = False


# Signal Handler, stop_program and exit safely
"""
    OS signal handle
"""
def signal_handler(signum=None, frame=None):
    global bShutdown
    bShutdown = True

def printHelp():
    print("help: ")
    print("    python3 test_cli_cmd.py <cli_cmd> <proof_in_answer> <serial-dev> (outputCli)")
    print("        outputCli: optional, if cli output show, type 'true'")
    print("\n    Note: You need access to the serial port. Maybe use sudo.")

def openUart(aComPort, aTimeOut=1):
    global serialUart
    serialUart = serial.Serial(aComPort,
                               115200,
                               timeout=aTimeOut,
                               parity=serial.PARITY_NONE,
                               rtscts=False,
                               stopbits=1,
                               bytesize=8)
    serialUart.flushInput()
    serialUart.flushOutput()
"""
    MAIN Routine
    Starts all Processes
"""
def main(argv):
    global bShutdown
    global serialUart
    global rxThread
    global reattemptByParseError
    global reattemptByError
    global bShowOutput

    exitCode = 1
    bShutdown = False

    # add signal handel for exit signals
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
        signal.signal(sig, signal_handler)

    print("CLI Test")

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

    # open serial port
    bConnected = False
    i = 0
    while(bConnected is False and i < reattemptByError):
        try:
            if('connect' in argv[1] or 'joiner' in argv[1] or 'commissioner' in argv[1]):
                openUart(argv[3], 5)
                bConnected = True
            elif('get' in argv[1] or 'put' in argv[1] or 'post' in argv[1]):
                openUart(argv[3], 4)
                bConnected = True
            else:
                openUart(argv[3], 1)
                bConnected = True
        except Exception as e:
            i += 1
            print("Error: " + e)

    if (i >= reattemptByError):
        print("cant open serial port")
        exit(1)

    parseError = True
    Error = True

    parseErrorCnt = 0
    errorCnt = 0

    while(parseErrorCnt < reattemptByParseError and (parseError or Error) and errorCnt < reattemptByError and not bShutdown):

        exitCode = 0

        try:
            serialUart.write((argv[1]+"\r\n").encode('UTF8'))
        except Exception as e:
            exitCode = 1
            print("cant write to serial device: " + argv[1])
            print("Error: " + e)
            errorCnt += 1
            Error = True
            parseError = False

        try:
            cmd = serialUart.read(1000)
        except Exception as e:
            print("Cant read answer: " + e)
            errorCnt += 1
            parseError = False
            Error = True
            exitCode = 1

        if (exitCode is 0):

            if(bShowOutput):
                print("\nCLI Output: \n" +cmd.decode('UTF8')+"\n")
            
            # check if proofing of result is desired
            if argv[2] != '':
                # proof result
                if argv[2] in cmd.decode('UTF8'):
                    exitCode = 0
                    print("CLI Test Done: PASS")
                    parseError = False
                    Error = False
                else:
                    exitCode = 1
                    # check if parse error (uart problem)
                    if "Error 6: Parse" in cmd.decode('UTF8'):
                        parseError = True
                        Error = False
                        parseErrorCnt += 1
                        exitCode = 1
                        print("CLI Test: Parse Error")
                    else:
                        Error = True
                        parseError = False
                        errorCnt += 1
                        exitCode = 1
                        print("CLI Test Done: FAIL")
            else:
                exitCode = 0
                print("CLI Test Done: PASS")
                parseError = False
                Error = False

    # done
    serialUart.close()
    sys.exit(exitCode)


# entry point of program
if __name__ == '__main__':
    if(len(sys.argv)>1):
        if("help" in sys.argv[1]):
            printHelp()
            exit(0)
    main(sys.argv)