from colorama import init, Fore
init(autoreset=True)

####################################################################
#       CONFIGURATION                                              #
####################################################################
# to switch the debug output on and off
dbgON = False
####################################################################


def log_print(s):
    ''' Print string s in log format '''
    print(Fore.GREEN + f"log: {s}...")


def dbg_print(s1, s2):
    ''' Print string s1 (title) \n string s2 (value) in dbg format '''
    if dbgON:
        print(Fore.CYAN + f"dbg: {s1}\n{s2}")


def err_print(s):
    ''' Print string s in log format '''
    print(Fore.RED + f"err: {s}...")
