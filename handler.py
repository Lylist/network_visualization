#!/usr/bin/python
# coding=utf-8

import sys
import os
import getopt
from data_process.processor import DataProcessor
os.environ["PATH"] += ';' + os.getcwd() + '\\visualization'
sys.path.append(os.getcwd()+'\\visualization')
sys.path.append('./data_process')

if __name__ == '__main__':
    argv = sys.argv[1:]
    input_file = ''
    file_type = 'csv'
    try:
        opts, args = getopt.getopt(argv, "hi:t:", ["ifile=", "filetype="])
    except getopt.GetoptError:
        print('-i <inputfile> -t <csv or pcap (default is csv)>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print("-i <inputfile> -t <csv or pcap (default is csv)>")
            sys.exit()
        elif opt in ('-i', '--ifile'):
            input_file = arg
        elif opt in ('-t', '--filetype'):
            if arg not in ('csv', 'pacp'):
                print('file_type is wrong. Please use -h!')
                sys.exit(2)
            file_type = arg

    print('file_type:%s' % file_type)
    print('input_file:%s' % input_file)
    processor = DataProcessor(input_file, file_type, save_path='data')
    processor.process()
    os.system('Blog-master.exe')
