#!/usr/bin/python
# coding=utf-8
import sys
import json
import math
from data_analyze.analysis import Analyzer

sys.path.append('../')


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

    def __init__(self, input_file='../data/data.csv', file_type='csv', save_path='../data'):
        self.res = []
        self.send = [[] for i in range(14405)]
        self.save_path = save_path
        self.input_file = input_file
        self.file_type = file_type
        self.ip_set = {}
        self.max_time = -1.0
        self.all_time = 144

    def _save_res(self):
        json_str = json.dumps({'point_data': self.res})
        with open(self.save_path + '/res.json', 'w') as wf:
            wf.write(json_str)
        wf.close()

    def _save_send(self):
        json_str = json.dumps({'send_data': self.send})
        with open(self.save_path + '/send.json', 'w') as wf:
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

    def add_point(self, source_ip, des_ip):
        '''
        添加一个节点对的节点信息
        :param source_ip: 源ip
        :param des_ip: 目的ip
        :return: 无
        '''
        if not self.ip_set.get(source_ip):
            new_id = len(self.ip_set)
            self.ip_set[source_ip] = new_id
            self.res.append(dict(id=new_id, ip=source_ip, link=set([]), device='computer',
                                 location=dict(x=0, y=0, z=0)))
        if not self.ip_set.get(des_ip):
            new_id = len(self.ip_set)
            self.ip_set[des_ip] = new_id
            self.res.append(dict(id=new_id, ip=des_ip, link=set([]), device='computer',
                                 location=dict(x=0, y=0, z=0)))
        des_id = self.ip_set[des_ip]
        source_id = self.ip_set[source_ip]
        self.res[des_id]['link'].add(source_id)
        self.res[source_id]['link'].add(des_id)

    def add_message(self, timestamp, source_ip, source_port, des_ip, des_port, protocol):
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
        if self.max_time < 0.0:
            raise Exception('ERROR: This data has wrong time data! --- max_time has wrong %f' %  self.max_time)
        try:
            index = math.ceil(self.all_time * float(timestamp) / self.max_time)
        except Exception as e:
            raise Exception('ERROR: This data has wrong time data! --- timestamp has wrong %s' % timestamp)

        if not (0 <= index < 14405):
            raise Exception('ERROR: This data has wrong time data! --- index has wrong')

        self.send[index].append(dict(srcID=self.ip_set[source_ip],
                                     desID=self.ip_set[des_ip],
                                     timeLength=1,
                                     sport=source_port,
                                     dport=des_port,
                                     protocol=protocol))

    def process_csv(self):
        '''
        对csv文件的处理，csv文件一定需要按照time, source_ip, source_port, des_ip, des_port, protocol存下来
        :return:
        '''
        # 寻找时间最大值
        is_first_line = True
        with open(self.input_file, 'rb') as f:
            for xline in f:
                if is_first_line:
                    is_first_line = False
                    continue
                try:
                    line = xline.decode('utf-8')
                    data = line.split(',')
                    real_time = data[0]

                    if '"' in real_time or "'" in real_time:
                        real_time = eval(real_time)

                except Exception as e:
                    continue
            self.max_time = max(self.max_time, float(real_time))
        f.close()

        is_first_line = True
        with open(self.input_file, 'rb') as f:
            for xline in f:
                if is_first_line:
                    is_first_line = False
                    continue
                # try:
                line = xline.decode('utf-8')
                data = line.split(',')
                real_time = data[0]
                source_ip = data[1]
                source_port = data[2]
                des_ip = data[3]
                des_port = data[4]
                protocol = data[5]

                if source_ip == '' or des_ip == '':
                    continue
                # 处理嵌套字符串的情况
                if '"' in real_time or "'" in real_time:
                    real_time = eval(real_time)
                self.add_point(source_ip, des_ip)
                self.add_message(real_time, source_ip, source_port, des_ip, des_port, protocol)

                # except Exception as e:
                #     print(str(e))
        f.close()

    def process_pcap(self):
        '''
        处理pcap包
        :return:
        '''
        pass

    def process(self):
        if self.file_type == 'csv':
            self.process_csv()
        else:
            self.process_pcap()

        analyzer = Analyzer(self.res)
        self.res = analyzer.process()

        # for p in self.res:
        #     print("%s: %s" % (p['id'], str(p['link'])))
        # self.remove_duplicates()
        self._save_res()
        self._save_send()
        print('sucess')


if __name__ == '__main__':
    process()

