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
#  File/Module:	    pre_install_checks.py
#
#  Coding/ Indent:  utf8/ whitespace
#
#  Author:          Christian Stauffer (stfc)
#                   Aurelio Schellenbaum (scnm)
#
#  Date, Version:   19.07.2018, V 0.1
#                   24.10.2019, V 1.0
#
#  Description:     This Module makes some checks, before run the whole test.
#                   E.g. check internet connectivity
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

def check_response(ping_response):

    if ping_response == 0:
        print('accessible')
        return True
    else:
        print('NOT accessible')
        return False

def check_connection_to(strIpUri):
    response = os.system("ping6 -c 1 " + str(strIpUri))
    return check_response(response)

def check_border_router_status(strIpUri, errorFlagLocation, local=False):
    if local == False:
        response = os.system("ssh allrounder@" + str(strIpUri) + " ls " + str(errorFlagLocation))
    else:
        response = os.system("ls " + str(errorFlagLocation))

    if response == 0:
        return False
    else:
        return True

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

    print("Pre Install Test\n")

    print("\n> Connection to Gatway")
    if not check_connection_to("2001:620:190:ffa1::1"):
        exit(1)
    print("\n> Connection to Internet (google)")
    if not check_connection_to("google.com"):
        exit(1)
    print("\n> Connection to Thread Testing Border Router")
    if not check_connection_to("2001:620:190:ffa1::9"):
        exit(1)
    print("\n> Connection to local Registrar")
    if not check_connection_to("2001:620:190:ffa1:21b:21ff:fe70:9240"):
        exit(1)
    print ("\n> Check Testing Border Router State")
    if not check_border_router_status('2001:620:190:ffa1::9', '/home/allrounder/error.flag'):
        exit(1)
    print ("\n> Check Testing POSIX Border Router State")
    if not check_border_router_status('2001:620:190:ffa1::2', '/media/hdd/share/posix_border_error.flag', True):
        exit(1)

    exit(0)

# entry point of program
if __name__ == '__main__':
    main()
