#!/usr/bin/python
# coding=utf-8

import queue
from functools import cmp_to_key
import math
PI = math.pi


class Analyzer(object):
    '''
        point: 所有点
        data: id与标记数组和逻辑的kv字典
        vis: 标记kv度
        r:钟表的半径
        circle_center: 圆心
        delta: 每次移动的角度偏量
        alpha: 当前钟表指针与x轴的夹角
        iniradius: 当前层，内环半径
    '''

    def __init__(self, point):
        self.point = point
        # 用于存id与点的kv对
        self.data = {}
        self.vis = {}

        self.iniradius = 5
        self.r = 5
        self.circle_center = {'x': 0.0, 'y': 0.0, 'z': 0.0}
        self.delta = PI/2
        self.alpha = 0

        self.dir = [[10, -10, 0, 0], [0, 0, 10, -10], [0, 0, 0, 0]]

    def sort(self, sort_list):
        '''
        用于排序，按节点度数排序
        :param sort_list: 传入要排序的list
        :return: 排好序的list
        '''
        length = len(sort_list)
        for i in range(length):
            for j in range(length-i-1):
                len1 = len(sort_list[j]['link'])
                len2 = len(sort_list[j+1]['link'])
                condition = lambda x: 1 if x < 5 else (2 if 5 <= x < 50 else 3)
                layer1 = condition(len1)
                layer2 = condition(len2)
                if len1 > len2 and layer1 != layer2:
                    k = sort_list[j]
                    sort_list[j] = sort_list[j+1]
                    sort_list[j+1] = k

        # sorted(sort_list, key=cmp_to_key(lambda x, y: len(x['link']) < len(y['link'])))
        return sort_list

    def block_init_begin(self):
        self.iniradius = 5
        self.r = 5
        self.circle_center = {'x': 0.0, 'y': 0.0, 'z': 0.0}
        self.delta = PI / 2
        self.alpha = 0

    def block_init_fulllayer(self):
        '''
        当铺完一层后初始化r、delta、alpha和circlr_center
        :return: 无返回值
        '''
        self.iniradius = (self.iniradius+self.r)/2
        self.r = self.iniradius
        self.delta = PI/2
        self.alpha = 0
        self.circle_center['x'] = 0.0
        self.circle_center['z'] = 0.0
        self.circle_center['y'] = self.circle_center['y']+40

    def block_init_fullcircle(self):
        '''
        当排满一圈后初始化r、delta和alpha
        :return: 无返回值
        '''
        self.r += self.iniradius
        self.delta = (PI/2)*(self.iniradius/self.r)
        self.alpha = 0

    def get_block_location(self):
        '''
        获取钟表算法中指针的坐标，同时动态维护钟表算法的
        :return: x,y,z值
        '''

        # 当排满一圈后需要重新确定r、delta和alpha
        if self.alpha >= PI * 2:
            self.block_init_fullcircle()

        x = self.r*math.cos(self.alpha)
        z = self.r*math.sin(self.alpha)
        y = self.circle_center['y']
        self.alpha += self.delta
        return x, y, z

    def location_plan(self, network):
        '''
        给一个网络按照钟表算法安排位置
        :param network: 一个是联通网络所有point的list
        :return: 无返回值，每个point的x,y,z坐标改变
        '''

        self.sort(network)

        self.r = 10
        self.circle_center = {'x': 0.0, 'y': 0.0, 'z': 0.0}
        self.delta = PI / 2
        self.alpha = 0
        layer2 = False
        layer3 = False
        for i, point in enumerate(network):
            index = self.data[point['id']]['index']
            length = len(point['link'])
            if length < 5:
                x, y, z = self.get_block_location()
                self.point[index]['location'].update(dict(x=x, y=y, z=z))
            if 5 <= length < 50:
                if not layer2:
                    layer2 = True
                    self.block_init_fulllayer()

                x, y, z = self.get_block_location()
                self.point[index]['location'].update(dict(x=x, y=y, z=z))
            if length >= 50:
                if not layer3:
                    layer3 = True
                    self.block_init_fulllayer()

                x, y, z = self.get_block_location()
                self.point[index]['location'].update(dict(x=x, y=y, z=z))

    def balance(self):
        pass

    def generate_location(self):
        bfs_queue = queue.Queue()
        network = []
        for i, p in enumerate(self.point):
            if self.data[p['id']].get('vis', False):
                continue

            bfs_queue.put(p)
            self.data[p['id']]['vis'] = True
            network.append(p)

            while(bfs_queue.empty() != True):
                p = bfs_queue.get()

                for nxt_id in p['link']:
                    if self.data[nxt_id].get('vis', False):
                        continue

                    nxt_p = self.point[self.data[nxt_id]['index']]
                    bfs_queue.put(nxt_p)
                    self.data[nxt_id]['vis'] = True
                    network.append(nxt_p)

        network = self.sort(network)
        self.location_plan(network)
        # for p in network:
        #     print("%s: %s" % (p['id'], str(p['link'])))

    def process(self):

        for i, p in enumerate(self.point):
            p['link'] = list(p['link'])
            self.data[p.get('id')] = dict(index=i)

        self.generate_location()
        self.balance()
        return self.point


if __name__ == '__main__':
    analyzer = Analyzer([])
    analyzer.process()
