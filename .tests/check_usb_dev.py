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
#  File/Module:	    check_usb_dev.py
#
#  Coding/ Indent:  utf8/ whitespace
#
#  Author:		    Christian Stauffer (stfc)
#
#  Date, Version:   19.07.2018, V 0.1
#
#  Description:     This module checks, if the devices are connected
#                  to the test server.
#
# ############################################################################ #

import signal   # for exit signal
import os


bShutdown = False
exitCode = 1


# Signal Handler, stop_program and exit safely
"""
    OS signal handle
"""
def signal_handler(signum=None, frame=None):
    global bShutdown
    global exitCode
    bShutdown = True

def check_usb_device(strDeviceAlias):
    response = os.system("ls -la /dev/"+str(strDeviceAlias))
    print(str(response))
    if response == 0:
        return True
    else:
        return False

"""
    MAIN Routine
    Starts all Processes
"""
def main():
    global bShutdown

    bShutdown = False

    # add signal handel for exit signals
    for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
        signal.signal(sig, signal_handler)

    print("Device Connect Test\n")

    print("\n> Connection to Testing Server Thread Node")
    if not check_usb_device("ttyCliServer"):
        exit(1)
    print("\n> Connection to Testing Client Thread Node")
    if not check_usb_device("ttyCliClient"):
        exit(1)

    exit(0)

# entry point of program
if __name__ == '__main__':
    main()
