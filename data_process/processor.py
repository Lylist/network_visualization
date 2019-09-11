#!/usr/bin/python
# coding=utf-8
import sys
import json
import math
import queue
from data_analyze.analysis import Analyzer
from scapy.all import *
import time
import gc

sys.path.append('../')

swith_list = ['Apple', 'Dell', 'Cisco', 'fe', 'Dell']


class DataProcessor(object):
    '''
        res: 所有节点的list
        send： 所有发送数据的list, 按时间轴存，共两个小时，每个item存0.5s的发文
        save_path: 数据存储的位置
        input_file: 源数据
        file_type: 数据类型，csv或者pcap
        ip_set：所有ip的集合
        max_time: 数据最大的时间戳
    '''

    def __init__(self, input_file='../data/data.csv', file_type='csv', all_time=14400, save_path='../data'):
        self.res = []
        self.send = []
        self.save_path = save_path
        self.input_file = input_file
        self.file_type = file_type
        self.ip_set = {}
        self.max_time = -1.0
        self.all_time = all_time
        self.msg_queue = []

    def _save_res(self):
        json_str = json.dumps({'point_data': self.res})
        with open(self.save_path + '/res.json', 'w') as wf:
            wf.write(json_str)
        wf.close()

    def _save_send(self):
        with open(self.save_path + '/send.json', 'w') as wf:
            for msg in self.send:
                json_str = str(msg['startTime']) + ' ' + str(msg['srcID']) + ' ' \
                           + str(msg['desID']) + ' ' + str(msg['timeLength']) + '\n'
                wf.write(json_str)
        wf.close()

    def remove_duplicates(self):
        '''
        去重，去除每个点link中的冗余，只留下从小到大的连接
        :return:
        '''
        for p in self.res:
            condition = lambda x: x < p['id']
            p['link'] = list(filter(condition, p['link']))
            
    def check_switch(self, ip):
        '''
        判断是否是交换机
        :param ip: ip
        :return: True or False
        '''
        for switch in swith_list:
            if switch in ip:
                return True
        
        return False

    def add_point(self, source_ip, des_ip):
        '''
        添加一个节点对的节点信息
        :param source_ip: 源ip
        :param des_ip: 目的ip
        :return: 无
        '''

        if self.ip_set.get(source_ip) == None:
            new_id = len(self.ip_set)
            self.ip_set[source_ip] = new_id
            if self.check_switch(source_ip):
                self.res.append(dict(id=new_id, ip=source_ip, link=set([]), device='switch',location=dict(x=0, y=0, z=0)))
            else:
                self.res.append(dict(id=new_id, ip=source_ip, link=set([]), device='computer',location=dict(x=0, y=0, z=0)))
        if self.ip_set.get(des_ip) == None:
            new_id = len(self.ip_set)
            self.ip_set[des_ip] = new_id
            if self.check_switch(des_ip):
                self.res.append(dict(id=new_id, ip=des_ip, link=set([]), device='switch',location=dict(x=0, y=0, z=0)))
            else:
                self.res.append(dict(id=new_id, ip=des_ip, link=set([]), device='computer',location=dict(x=0, y=0, z=0)))
        
        try:
            des_id = self.ip_set[des_ip]
            source_id = self.ip_set[source_ip]
            self.res[des_id]['link'].add(source_id)
            self.res[source_id]['link'].add(des_id)
        except Exception as e:
            raise Exception("ip has wrong (%s %s)" % (source_ip, des_ip))

    def add_message(self, timestamp, source_ip, des_ip):
        '''
        添加一条数据报
        :param timestamp: 发报文时间
        :param source_ip: 源ip
        :param source_port: 源ip端口
        :param des_ip: 目的ip
        :param des_port: 目的ip端口
        :param protocol: 协议
        :return: 无
        '''

        try:
            startTime = float(timestamp)
        except Exception:
            startTime = float(eval(timestamp))

        try:
            self.max_time = max(startTime, self.max_time)
        except Exception:
            raise Exception('Time data is wrong %s !' % str(timestamp))

        self.msg_queue.append(dict(startTime=startTime,
                                srcID=self.ip_set[source_ip],
                                desID=self.ip_set[des_ip],
                                timeLength=1))

    def trans_time_axis(self):
        '''
        将时间映射到固定时间轴
        :return:
        '''
        if self.max_time < 0.0:
            raise Exception('ERROR: This data has wrong time data! --- max_time has wrong %f' %  self.max_time)

        last_msg = None
        for msg in self.msg_queue:
            # msg = self.msg_queue.get()
            try:
                index = math.ceil(self.all_time * msg['startTime'] / self.max_time)
            except Exception:
                raise Exception('ERROR: This data has wrong time data! --- timestamp has wrong %s' % timestamp)

            if not (0 <= index < 14405):
                raise Exception('ERROR: This data has wrong time data! --- index has wrong')

            msg.update({'startTime':index})
            if last_msg and msg['startTime'] == last_msg['startTime'] and \
                            ((msg['srcID'] == last_msg['srcID'] and msg['desID'] == last_msg['desID']) or
                             (msg['srcID'] == last_msg['desID'] and msg['desID'] == last_msg['srcID'])):
                continue

            self.send.append(msg)
            last_msg = msg

    def process_csv(self):
        '''
        对csv文件的处理，csv文件一定需要按照time, source_ip, source_port, des_ip, des_port, protocol存下来
        :return:
        '''

        is_first_line = True

        read_time = 0
        add_point_time = 0
        add_msg_time = 0
        cnt = 0
        sum = 1

        with open(self.input_file, 'rb') as f:
            for xline in f:
                cnt += 1
                if cnt > 1000000:
                    print('已处理%d条' % (sum*1000000))
                    sum += 1
                    cnt = 0

                t0 = time.time()
                if is_first_line:
                    is_first_line = False
                    continue
                try:
                    line = xline.decode('utf-8')
                    data = line.split(',')
                    real_time = data[0]
                    source_ip = data[1]
                    des_ip = data[3]

                except Exception as e:
                    continue

                if source_ip == '' or des_ip == '':
                    continue
                read_time += time.time() - t0
                t0 = time.time()
                self.add_point(source_ip, des_ip)
                add_point_time += time.time() - t0
                t0 = time.time()
                self.add_message(real_time, source_ip, des_ip)
                add_msg_time += time.time() - t0

        f.close()
        print("读文件耗时：%f" % read_time)
        print("处理节点信息耗时：%f" % add_point_time)
        print("报文消息处理耗时： %f" % add_msg_time)

    def process_pcap(self):
        is_first_line = True
        time = 0
        pcap = rdpcap(self.input_file)
        cnt = 0
        sum = 1

        for data in pcap:
            time += 1

            cnt += 1
            if cnt > 1000000:
                print('已处理%d条' % (sum * 1000000))
                sum += 1
                cnt = 0

            if is_first_line:
                is_first_line = False
                continue
            try:
                real_time = time
                time += 1
                source_ip = data[IP].src
                des_ip = data[IP].dst

            except Exception as e:
                continue

            if source_ip == '' or des_ip == '':
                continue

            self.add_point(source_ip, des_ip)
            self.add_message(real_time, source_ip, des_ip)

    def process(self):
        if self.file_type == 'csv':
            self.process_csv()
        else:
            self.process_pcap()
        gc.collect()

        t0 = time.time()
        analyzer = Analyzer(self.res)
        self.res = analyzer.process()
        print("位置计算耗时： %f" % (time.time() - t0))
        gc.collect()
        # t0 = time.time()
        self._save_res()
        # print(time.time() - t0)
        # t0 = time.time()
        self.trans_time_axis()
        # print(time.time() - t0)
        # t0 = time.time()
        self._save_send()
        # print(time.time() - t0)
        print('sucess')


if __name__ == '__main__':
    process()

