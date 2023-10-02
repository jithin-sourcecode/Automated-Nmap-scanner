import argparse, textwrap
import Nmap_Scanner 



if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Automated Nmap Scan',formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument('-i','--IP', type=str,
                                    help='Provide the ip address for scanning') 
        parser.add_argument('-s','--SCAN', type=str, choices=['TCP', 'UDP', 'FULL'],
                                    help= textwrap.dedent('''\
                                    BY Default TCP Scan will Run 
                                    TCP SCAN - TCP
                                    UDP SCAN - UDP
                                    FULL SCAN - FULL '''),default='TCP')
    except:
        parser.print_help()

    args = vars(parser.parse_args())

    if None in args.values():
        parser.print_help()
        exit(1)
    if args['SCAN'] == 'TCP':
        Nmap_Scanner.TCPSCAN(args['IP'])
    if args['SCAN'] == 'UDP':
        Nmap_Scanner.UDPSCAN(args['IP'])
    if args['SCAN'] == 'FULL':
        Nmap_Scanner.FULLSCAN(args['IP'])
