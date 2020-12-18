import Log_Parser
import Log_Analizer
import Sniffer
import argparse
import time

LOG_FILE = r'C:\Users\Owner\PycharmProjects\SIEM\log_file.txt'
LOG_SNIFF = r'C:\Users\Owner\PycharmProjects\SIEM\sniff_log_file.txt'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('op', type=str, choices=['parse', 'analise', 'sniff'], help='Enter a option')
    parser.add_argument('--file', type=str, choices=[LOG_FILE, LOG_SNIFF], help='Enter a file for options "sniff" and "parse"')
    parser.add_argument('--func', type=str, choices=['spo', 'pos', 'pis', 'pist', 'all'], help='Enter a function for option "analise" to '
                'detect attack: spo - Specific Port; pos - Port Scan; pis - Ping Swip; pist - Ping Swip with time; all - all sort of attacks')
    parser.add_argument('--port', type=int, help='Enter a port for detect Specific Port attack')
    parser.add_argument('--time', type=int, help='Enter a time in seconds for time differences to Ping Sweep attack conditions')


    args = parser.parse_args()
    # parse option
    if args.op == 'parse':
        if args.file == LOG_SNIFF:
            # writing to DB from Sniffer log file
            Log_Parser.readLogFileFromSniffer(args.file)
        else:
            # writing to DB from log file
            Log_Parser.readLogFilefromFile(args.file)
    # sniff option
    elif args.op == 'sniff':
        with open(args.file, 'a') as f:
            Sniffer.sniffPackets(f)
    # analise option
    elif args.op == 'analise':
        if args.func == 'spo':
        # detecting Specific Port attack
            Log_Analizer.specificPort(args.port)
        elif args.func == 'pos':
        # detecting Port Scan attack
            Log_Analizer.portScan()
        elif args.func == 'pis':
        # detecting Ping Swip attack
            Log_Analizer.pingSweep()
        elif args.func == 'pist':
        # detecting Ping Swip with time attack
            Log_Analizer.pingSweepWithTime(args.time)
        elif args.func == 'all':
        # detecting all sort of attacks
            while True:
                Log_Analizer.specificPort(args.port)
                Log_Analizer.portScan()
                Log_Analizer.pingSweep()
                Log_Analizer.pingSweepWithTime(args.time)
                time.sleep(5)
                continue

if __name__ == '__main__':
    main()