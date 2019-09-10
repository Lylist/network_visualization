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
    my_time = 14400

    try:
        opts, args = getopt.getopt(argv, "hi:t:x:", ["help", "ifile=", "filetype=", "timelength="])
    except getopt.GetoptError:
        print('-i <inputfile> -t <csv or pcap (default is csv)>')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print("-i <inputfile> -t <csv or pcap (default is csv)> -x <show time>")
            sys.exit()
        elif opt in ('-i', '--ifile'):
            input_file = arg
        elif opt in ('-t', '--filetype'):
            if arg not in ('csv', 'pcap'):
                print('file_type is wrong. Please use -h!')
                sys.exit(2)
            file_type = arg
        elif opt in ('-x', '--timelength'):
            try:
                my_time = int(arg)
            except Exception:
                print('time is wrong')
                sys.exit(2)
            my_time = my_time

    print('file_type:%s' % file_type)
    print('input_file:%s' % input_file)
    print('my_time:%s' % my_time)
    processor = DataProcessor(input_file, file_type, my_time, save_path='data')
    processor.process()
    os.system('Blog-master.exe')
