#!/usr/bin/env python

import json
import re
import socket, struct
import getopt,os,sys
import pyroute2
import fcntl
import smp
#from pyroute2 import IPRoute

inttoip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
iptoint = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])

dev2idx = {}
lockfile = "/tmp/jznat_proc.lock"
lockf = None
kernel_rules = []
none_tcp = False
ipt_opts = None
nopersistent = False
ipt_random = False

def get_dev_idx(dev):
    if dev in dev2idx:
        return dev2idx[dev]
    ip = pyroute2.IPRoute()
    idx = ip.link_lookup(ifname=dev)[0]
    dev2idx[dev] = idx
    ip.close()
    return idx

def get_ip_addr():
    ips = []
    f = os.popen("ip addr")
    for i in f:
        content = i.split()
        if content[0] == 'inet':
            ips.append(content[1].split('/')[0])
    f.close()
    return ips

def get_default_route():
    f = os.popen('ip route')
    lines = []
    tmp_line = ''
    for line in f:
        if line[0] != '\t' and tmp_line != '':
            lines.append(tmp_line)
            tmp_line = line.strip('\n ')
        else:
            tmp_line += line.strip('\n ').replace('\t', ' ')
    if tmp_line != '':
        lines.append(tmp_line)
    f.close()
    default_rt = None
    for line in lines:
        default_rt = jz_route(line)
        if default_rt.addr == 'default':
            break
    return default_rt

class jz_addr:
    def __init__(self, straddr):
        self.ip = None
        self.prefix = None
        self.ip_start = None
        self.ip_end = None
        straddr = straddr.strip()
        pattern_ip = re.compile(r'(^\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}$)')
        pattern_ipprefix = re.compile(r'(^\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})/(\d{1,2}$)')
        pattern_iprange = re.compile(r'(^\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})-(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}$)')
        match = pattern_ip.match(straddr)
        if match:
            self.ip = straddr
            self.prefix = 32
            return
        match = pattern_ipprefix.match(straddr)
        if match:
            self.ip = match.group(1)
            self.prefix = int(match.group(2))
            return
        match = pattern_iprange.match(straddr)
        if match:
            self.ip_start = match.group(1)
            self.ip_end = match.group(2)

    def addrs(self):
        ips = []
        if self.ip:
           ips.append(self.ip)
        elif self.ip_start and self.ip_end:
            a = iptoint(self.ip_start)
            b = iptoint(self.ip_end)
            for i in range(a, b+1):
                ips.append(inttoip(i))
        return ips

class jz_route_hop:
    def __init__(self, s):
        self.gw = None
        self.weight = None
        self.dev = None
        content = s.split(' ')
        for i in range(len(content)):
            if content[i] == 'via':
                self.gw = content[i+1]
            elif content[i] == 'weight':
                self.weight = content[i+1]
            elif content[i] == 'dev':
                self.dev = content[i+1]

    def __cmp__(self, obj):
        if (self.gw == obj.gw and self.weight == obj.weight): 
            if self.dev and obj.dev and self.dev != obj.dev:
                return -1
            return 0
        else:
            return -1

class jz_route:
    def __init__(self, s):

        sh = s.split('nexthop')
        content = sh[0].split()
        self.addr = self.fixaddr(content[0])
        self.hops = []
        self.proto = None
        self.src = None
        for i in range(len(content)):
            if content[i] == 'proto':
                self.proto = content[i+1]
            if content[i] == 'src':
                self.src = content[i+1]
        if len(sh) > 1:
            for h in sh[1:]:
                hop = jz_route_hop(h)
                self.hops.append(hop)
        else:
            hop = jz_route_hop(sh[0])
            self.hops.append(hop)

    def fixaddr(self, addr):
        if addr == 'default':
            return addr
        if addr.find('/') < 0:
            return addr + '/32'
        return addr
        ip = addr.split('/')[0]
        mask = int(addr.split('/')[1])
        sub = 32 - mask
        nip = iptoint(ip)
        nip = (nip >> sub) << sub
        new = inttoip(nip)
        return "%s/%d" % (new, mask)


    def __cmp__(self, obj):
        if self.addr == obj.addr and self.src == obj.src and self.hops == obj.hops:
            return 0
        else:
            return -1

    def isaddrin(self, obj):
        return self.addr == obj.addr

    def __str__(self):
        s = self.addr
        if len(self.hops) == 1:
            if self.hops[0].gw:
                s += ' via ' + self.hops[0].gw
            if self.hops[0].weight:
                s += ' weight ' + self.hops[0].weight
            if self.hops[0].dev:
                s += ' dev ' + self.hops[0].dev
            if self.src:
                s += ' src ' + self.src
        else:
            if self.src:
                s += ' src ' + self.src
            for hop in self.hops:
                s += ' nexthop'
                if hop.gw:
                    s += ' via ' + hop.gw
                if hop.weight:
                    s += ' weight ' + hop.weight
                if hop.dev:
                    s += ' dev ' + hop.dev

        return s

    def spec(self, s):
        s['prefsrc'] = None
        if self.src:
            s['prefsrc'] = self.src
        s['dst'] = self.addr
        if len(self.hops) == 1:
            if self.hops[0].gw:
                s['gateway'] = self.hops[0].gw
            if self.hops[0].dev:
                s['oif'] = get_dev_idx(self.hops[0].dev)
        else:
            mp = []
            for hop in self.hops:
                path = {}
                path['gateway'] = hop.gw
                path['hops'] = int(hop.weight) - 1
                if hop.dev:
                    path['oif'] = get_dev_idx(hop.dev)
                mp.append(path)
            s['multipath'] = mp

def load_kernel_rules():
    f = os.popen('ip route show')
    lines = []
    tmp_line = ''
    for line in f:
        if line[0] != '\t' and tmp_line != '':
            lines.append(tmp_line)
            tmp_line = line.strip('\n ')
        else:
            tmp_line += line.strip('\n ').replace('\t', ' ')
    if tmp_line != '':
        lines.append(tmp_line)
    f.close()
    for line in lines:
        rt = jz_route(line)
        if rt.proto == 'kernel':
            kernel_rules.append(rt)

class jz_table:
    def __init__(self, name, idx):
        self.name = name
        self.idx = idx
    def load(self, data, addrgroup, outlink):
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2})[ \t]+via[ \t]+(.+)')
        group_pattern = re.compile(r'(.+)[ \t]+via[ \t]+(.+)')
        self.routes = []
        self.routerules = {} 
        for r in data:
            match = ip_pattern.match(r)
            if match:
                addr = match.group(1)
                out = match.group(2)
                if not outlink.exist(out):
                    print '"%s" in "%s" not configured, ignore' % (out, r)
                    continue
                self.routes.append(r)
                r = addr + ' ' + outlink.outlink[out].route_rule()
                #self.routerules.append(jz_route(r))
                rt = jz_route(r)
                self.routerules[rt.addr] = rt

            else:
                match = group_pattern.match(r)
                if not match:
                    print '"%s" error, ignore' % (r)
                    continue
                group = match.group(1)
                out = match.group(2)
                if group == 'default' and self.name == 'main' and force_main_default == False:
                    print "'%s' main table can't change defualt route" % (r)
                    continue

                if not outlink.exist(out):
                    print '"%s" in "%s" not configured, ignore' % (out, r)
                    continue
                if not addrgroup.exist(group):
                    print '"%s" in "%s" not configured, ignore' % (group, r)
                    continue
                self.routes.append(r)
                for addr in addrgroup.addrgroup[group]:
                    r = addr + ' ' + outlink.outlink[out].route_rule()
                    rt = jz_route(r)
                    self.routerules[rt.addr] = rt
                    #self.routerules.append(jz_route(r))
        for i in kernel_rules:
            self.routerules[i.addr] = i

    def show(self):
        print self.name
        for _,rule in self.routerules.items():
            print rule

    def load_sys(self):
        self.sys_routerules = {} 
        f = os.popen('ip route show table %d' % (self.idx))
        lines = []
        tmp_line = ''
        for line in f:
            if line[0] != '\t' and tmp_line != '':
                lines.append(tmp_line)
                tmp_line = line.strip('\n ')
            else:
                tmp_line += line.strip('\n ').replace('\t', ' ')
        if tmp_line != '':
            lines.append(tmp_line)
        f.close()
        for line in lines:
            rt = jz_route(line)
            self.sys_routerules[rt.addr]  = rt;
            #self.sys_routerules.append(jz_route(line))

    def gen_act(self):
        self.load_sys()
        self.acts = []
        self.pyroute_acts = []
        for addr,i in self.routerules.items():
            if addr not in self.sys_routerules or i != self.sys_routerules[addr]:
                act = 'ip route replace table %s %s' % (self.name, str(i))
                self.acts.append(act)
                s = {}
                s['cmd'] = 'replace'
                s['table'] = self.idx
                i.spec(s)
                self.pyroute_acts.append(s)
        for addr,i in self.sys_routerules.items():
            if addr not in self.routerules:
                if self.name == 'main' and (i.proto == 'kernel' or i.addr == 'default' or i.addr == '0.0.0.0' or i.addr == '169.254.0.0/16'):
                    continue
                act = 'ip route del table %s %s' % (self.name, str(i))
                self.acts.append(act)
                s = {}
                s['cmd'] = 'del'
                s['table'] = self.idx
                i.spec(s)
                self.pyroute_acts.append(s)


class jz_outtable:
    def __init__(self):
        self.rtfile = '/etc/iproute2/rt_tables'
        self.name2id = {}
        self.id2name = {}
        self.rtfile_change = False
        with open(self.rtfile) as f:
            for line in f:
                if line[0] == '#':
                    continue
                line = line.strip('\n')
                v = line.split('\t')
                if v[1] not in self.name2id:
                    self.name2id[v[1]] = int(v[0])
                    self.id2name[int(v[0])] = v[1]

    def load_data(self, data, exptype):
        if type(data) is exptype:
            return data
        elif type(data) is unicode:
            try:
            	f = open(data, 'r')
            	var = json.load(f)
            	f.close()
            	return var
	    except Exception,e:
                print("load %s error:%s" % (data, str(e)))
                lockf.close()
                sys.exit(1)

    def get_id(self, name):
        if name in self.name2id:
            return self.name2id[name]
        for i in range(1, 252):
            if i not in self.id2name:
                self.name2id[name] = i
                self.id2name[i] = name
                self.rtfile_change = True
                return i

    def gen_rt_table(self):
        if not self.rtfile_change:
            return
        f = open(self.rtfile, 'w')
        f.write('#\n255\tlocal\n254\tmain\n253\tdefault\n0\tunspec\n#\n# local\n#\n')
        for i in range(1,252):
            if i in self.id2name:
                f.write('%d\t%s\n' % (i, self.id2name[i]))
        f.close()

    def show_rt_table(self):
        print '#\n255\tlocal\n254\tmain\n253\tdefault\n0\tunspec\n#\n# local\n#'
        for i in range(1,252):
            if i in self.id2name:
                print '%d\t%s' % (i, self.id2name[i])


    def load(self, data, addrgroup, outlink):
        self.rt_tables = {}
        for name,route in data.items():
            route = self.load_data(route, list)
            if name == 'local' or name == 'default' or name == 'unspec':
                print 'table name %s is reserved, ignore' % (name)
                continue
            if name in self.rt_tables:
                print 'table name %s repeated, ignore latter' %s (name)
                continue
            table = jz_table(name, self.get_id(name))
            table.load(route, addrgroup, outlink)
            self.rt_tables[name] = table

        self.gen_act()

    def gen_act(self):
        self.acts = []
        self.pyroute_acts = []
        for name, route in self.rt_tables.items():
            route.gen_act()
            self.acts += route.acts
            self.pyroute_acts += route.pyroute_acts

    def show_act(self):
        for i in self.acts:
            print i

    def apply(self):
        self.gen_rt_table()
        #for i in self.acts:
        #    ret = os.system(i)
        #    if ret != 0:
        #        print '"%s" failed' % (i)
        ip = pyroute2.IPRoute()
        for i in self.pyroute_acts:
            try:
                if i.has_key('gateway'):
                    ip.route(i['cmd'], table=i['table'],dst=i['dst'], gateway=i['gateway'], prefsrc=i['prefsrc'])
                elif i.has_key('multipath'):
                    ip.route(i['cmd'], table=i['table'],dst=i['dst'], multipath=i['multipath'], prefsrc=i['prefsrc'])
                else:
                    ip.route(i['cmd'], table=i['table'],dst=i['dst'], prefsrc=i['prefsrc'], oif=i['oif'])
            except Exception,e:
                print(str(e))
        ip.close()

    def exist(self, name):
        return name in self.rt_tables

    def show(self):
        for name, route in self.rt_tables.items():
            route.show()

        
class jz_single_out:
    def __init__(self, s):
        content = s.split(' ')
        self.weight = "1"
        for i in range(len(content)):
            if content[i] == 'src':
                self.src = content[i+1]
            elif content[i] == 'gw':
                self.gw = content[i+1]
            elif content[i] == 'w':
                self.weight = content[i+1]
            elif content[i] == 'nat':
                self.nat = int(content[i+1])
            

class jz_out:
    def __init__(self, sv):
        self.out = []
        for s in sv:
            out = jz_single_out(s)
            self.out.append(out)
        self.defrt = get_default_route()

    def ip2int(self, ip):
        return socket.htonl(iptoint(ip))

    def route_rule(self):
        if len(self.out) == 1:
            rule = 'via ' + self.out[0].gw
            if self.out[0].src:
                rule += ' src ' + self.out[0].src.split('-')[0]
            return rule
        elif len(self.out) > 1:
            rule = None
            if self.out[0].src:
                rule = 'src ' + self.out[0].src.split('-')[0]
            #for so in self.out:
            for i in range(len(self.out)):
                so =  self.out[i]
                j = i
                while j >= len(self.defrt.hops):
                    j -= len(self.defrt.hops)
                dev = self.defrt.hops[j].dev
                devstr = ''
                if dev and so.nat:
                    devstr = ' dev ' + dev
                if not rule:
                    rule = 'nexthop via ' + so.gw + ' weight ' + so.weight + devstr
                else:
                    rule += ' nexthop via ' + so.gw + ' weight ' + so.weight + devstr
            return rule

    def nat_rule(self):
        rules = []
        global ipt_opts
        lipt_ops = ""
        snat_opt = "--persistent"
        if none_tcp:
            if ipt_opts:
                lipt_opts = ipt_opts + " ! -p tcp"
            else:
                lipt_opts = "! -p tcp"
        else:
            lipt_opts = ipt_opts
        if nopersistent:
            snat_opt = ""
        if ipt_random:
            snat_opt = snat_opt + " --random"
        for so in self.out:
            if so.nat != 0:
                if lipt_opts:
                    rule = '-A POSTROUTING %s -m mark --mark 0x%x -j SNAT --to-source %s %s' % (lipt_opts, self.ip2int(so.gw), so.src, snat_opt)
                else:
                    rule = '-A POSTROUTING -m mark --mark 0x%x -j SNAT --to-source %s %s' % (self.ip2int(so.gw), so.src, snat_opt)
                rules.append(rule)
        return rules



class jz_outlink:
    def __init__(self):
        self.outlink = {}
        self.nat_rules = []

    def load_data(self, data, exptype):
        if type(data) is exptype:
            return data
        elif type(data) is unicode:
            f = open(data, 'r')
            var = json.load(f)
            f.close()
            return var

    def exist(self, name):
        return name in self.outlink

    def load(self, data):
        for name,link in data.items():
            linkinfo = self.load_data(link, list)
            out = jz_out(linkinfo)
            self.outlink[name] = out
            self.nat_rules += out.nat_rule()

        if not self.gw_check():
            lockf.close()
            sys.exit()

        self.gen_act()

    def load_sys(self):
        self.sys_nat_rules = []
        f = os.popen('iptables-save')
        begin = False
        for line in f:
            line = line.strip()
            if line[0] == '#' or line[0] == ':':
                continue
            if line == '*nat':
                begin = True
                continue
            if line == 'COMMIT':
                begin = False
                continue
            if begin:
                self.sys_nat_rules.append(line)
        f.close()

    def gen_act(self):
        self.load_sys()
        self.acts = []
        for i in self.sys_nat_rules:
            if i not in self.nat_rules:
                act = 'iptables -t nat %s' % (i.replace('-A', '-D'))
                self.acts.append(act)
        for i in self.nat_rules:
            if i not in self.sys_nat_rules:
                act = 'iptables -t nat %s' % (i)
                self.acts.append(act)

    def show_act(self):
        for i in self.acts:
            print i

    def show(self):
        for i in self.nat_rules:
            print i

    def apply(self):
        for i in self.acts:
            ret = os.system(i)
            if ret != 0:
                print '"%s" failed' % (i)

    def src_list(self):
        src = []
        for _,out in self.outlink.items():
            for so in out.out:
                if so.nat == 0:
                    continue
                for i in jz_addr(so.src).addrs():
                    src.append(i)
        return list(set(src))

    def gw_list(self):
        gw = []
        for _,out in self.outlink.items():
            tgw = []
            for so in out.out:
                for i in jz_addr(so.gw).addrs():
                    tgw.append(i)
            gw.append(tgw)
        return gw

    def gw_all(self):
        gw = []
        for _,out in self.outlink.items():
            for so in out.out:
                for i in jz_addr(so.gw).addrs():
                    gw.append(i)
        return list(set(gw))
    
    def gw_check(self):
        gw = set()
        for _,out in self.outlink.items():
            for so in out.out:
                for i in jz_addr(so.gw).addrs():
                    if i in gw:
                        print('error:gw %s repeat' % (i))
                        return False
                    gw.add(i)
        return True


    #def setup(self):
    #    for _,out in self.outlink.items():
    #        out.setup()


class jz_addrgroup:
    def load_data(self, data, exptype):
        if type(data) is exptype:
            return data
        elif type(data) is unicode:
            try:
            	f = open(data, 'r')
            	var = json.load(f)
            	f.close()
            	return var
	    except Exception,e:
                print("load %s error:%s" % (data, str(e)))
                lockf.close()
                sys.exit(1)

    def load(self, data):
        self.addrgroup = {"default":["default"]}
        for name,group in data.items():
            self.addrgroup[name] = self.load_data(group, list)
    def exist(self, name):
        return name in self.addrgroup

    def show(self):
        print self.addrgroup

class jz_src_rule:
    def load(self, data, addrgroup, outtable):
        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2})[ \t]+via[ \t]+(.+)')
        group_pattern = re.compile(r'(.+)[ \t]+via[ \t]+(.+)')
        self.addr_rule = []
        self.group_rule = []
        self.iprules = []
        for rule in data:
           match = ip_pattern.match(rule)
           if match:
               addr = match.group(1)
               table = match.group(2)
               if not outtable.exist(table):
                   print '"%s" in "%s" not configured, ignore' % (table, rule)
                   continue
               self.addr_rule.append(rule)
               rule = 'from ' + self.fixaddr(addr) + ' lookup ' + table
               self.iprules.append(rule)
           else:
               match = group_pattern.match(rule)
               if not match:
                   print '"%s" error, ignore' % (rule)
                   continue
               group = match.group(1)
               table = match.group(2)
               if not addrgroup.exist(group):
                   print '"%s" in "%s" not configured, ignore' % (group, rule)
                   continue
               if not outtable.exist(table):
                   print '"%s" in "%s" not configured, ignore' % (table, rule)
                   continue
               self.group_rule.append(rule)
               for addr in addrgroup.addrgroup[group]:
                   rule = 'from ' + self.fixaddr(addr) + ' lookup ' + table
                   self.iprules.append(rule)

        self.gen_act()

    def show(self):
        for i in self.acts:
            print i

    def fixaddr(self, addr):
        s = addr.find('/32')
        if s >= 0:
            return addr[:s]
        return addr

    def load_sys(self):
        self.sys_iprules = []
        f = os.popen('ip rule show')
        for line in f:
            line = line.strip()
            #table = line.split(' ')[-1]
            ruleid = int(line.split(':')[0])
            #if table == 'local' or table == 'main' or table == 'default':
            #    continue
            if ruleid < 100 or ruleid > 32765:
                continue
            #self.sys_iprules.append(line.split('\t')[1])
            self.sys_iprules.append(line)
        f.close()

    def rule_key(self, rule):
        addr = jz_addr(rule.split(' ')[1])
        #print(rule.split(' ')[1], addr.prefix)
        return addr.prefix 

    def gen_act(self):
        self.load_sys()
        self.acts = []
        sys_map = {}
        act_map = {}
        sys_rules = []
        for i in self.sys_iprules:
            st = i.split(':\t')
            if st[1] not in self.iprules:
                act = 'ip rule del %s' % (st[1])
                self.acts.append(act)
            else:
                sys_map[int(st[0])] = st[1]
                sys_rules.append(st[1])
        rules = sorted(self.iprules, key = self.rule_key)
        idx = 32765
        for i in rules:
            if idx in sys_map:
                if i == sys_map[idx]:
                    del sys_map[idx]
                    idx -= 1
                    continue
                act = 'ip rule del %s pref %d' % (sys_map[idx], idx)
                self.acts.append(act)
                del sys_map[idx]
            act = 'ip rule add %s pref %d' % (i, idx)
            self.acts.append(act)
            idx -= 1
        for i,k in sys_map.items():
            act = 'ip rule del %s pref %d' % (k,i )
            self.acts.append(act)

    def show_act(self):
        for i in self.acts:
            print i

    def apply(self):
        for i in self.acts:
            ret = os.system(i)
            if ret != 0:
                print '"%s" failed' % (i)

class ifcfg_handle:
    def __init__(self, device):
        self.data = {}
        self.fname = "/etc/sysconfig/network-scripts/ifcfg-" + device
        self.ips = {}
        if os.path.exists(self.fname):
            f = open(self.fname)
            for line in f:
                if line[0] == "#":
                    continue
                ct = line.strip().split('=')
                self.data[ct[0]] = ct[1]
            f.close()
        if "DEVICE" not in self.data:
            self.data["DEVICE"] = device
        if "BOOTPROTO" not in self.data:
            self.data["BOOTPROTO"] = "none"
        if "ONBOOT" not in self.data:
            self.data["ONBOOT"] = "yes"
        if device.find("lo") == 0 and "NAME" not in self.data:
            self.data["NAME"] = "loopback0"
        if "IPADDR" in self.data:
            if "NETMASK" in self.data:
                self.ips[self.data["IPADDR"]] = self.data["NETMASK"]
            elif "PREFIX" in self.data:
                self.ips[self.data["IPADDR"]] = self.prefix2mask(self.data["PREFIX"])
            else:
                self.ips[self.data["IPADDR"]] = "255.255.255.255"
        for i in range(256):
            if "IPADDR"+str(i) in self.data:
                if "NETMASK"+str(i) in self.data:
                    self.ips[self.data["IPADDR"+str(i)]] = self.data["NETMASK"+str(i)]
                elif "PREFIX"+str(i) in self.data:
                    self.ips[self.data["IPADDR"+str(i)]] = self.prefix2mask(self.data["PREFIX"+str(i)])
                else:
                    self.ips[self.data["IPADDR"+str(i)]] = "255.255.255.255"

    def set(self, k, v):
        self.data[k] = v

    def prefix2mask(self, prefix):
        return inttoip(~((1 << (32 - prefix)) - 1))

    def add_addr(self, ip, prefix):
        if ip in self.ips:
            return
        newname = None
        for i in range(256):
            newname = "IPADDR" + str(i)
            if newname not in self.data:
                break
        if not newname:
            print("too many ip, exit")
            lockf.close()
            sys.exit(1)
        mask = self.prefix2mask(prefix)
        self.data[newname] = ip
        self.data["NETMASK"+str(i)] = mask

    def apply(self):
        f = open(self.fname, "w")
        for k,v in self.data.items():
            f.write("%s=%s\n" % (k,v))
        f.close()

class jznat:
    def load_data(self, data, exptype):
        if type(data) is exptype:
            return data
        elif type(data) is unicode:
	    try:
            	f = open(data, 'r')
            	var = json.load(f)
            	f.close()
            	return var
	    except Exception,e:
                print("load %s error:%s" % (data, str(e)))
                lockf.close()
                sys.exit(1)

    def load(self, conffile):
        f = open(conffile, 'r')
        self.conf = json.load(f)
        f.close()
        self.outlink = jz_outlink()
        self.outlink.load(self.load_data(self.conf['outlink'], dict))
        self.addrgroup = jz_addrgroup()
        self.addrgroup.load(self.load_data(self.conf['addrgroup'], dict))
        self.outtable = jz_outtable()
        self.outtable.load(self.load_data(self.conf['outtable'], dict), self.addrgroup, self.outlink)
        self.src_rule = jz_src_rule()
        self.src_rule.load(self.load_data(self.conf['src_rule'], list), self.addrgroup, self.outtable)

    def show(self):
        #self.outtable.show_rt_table()
        self.outtable.show_act()
        self.src_rule.show_act()
        self.outlink.show_act()

    def apply(self, ask=True):
        if ask:
            inputstr= raw_input("apply change?[y/N]")
            if inputstr != 'y' and inputstr != 'Y':
                return
        self.setup()
        self.outlink.apply()
        self.outtable.apply()
        self.src_rule.apply()

    def config_ip(self,ip,prefix):
        confip = []
        f = os.popen("grep -h IPADDR /etc/sysconfig/network-scripts/ifcfg-lo* | cut -d '=' -f 2")
        for i in f:
            confip.append(i.strip())
        f.close()
        if ip in confip:
            return
        confname = []
        f = os.popen("grep -h IPADDR /etc/sysconfig/network-scripts/ifcfg-lo:nat 2> /dev/null | cut -d '=' -f 1")
        for i in f:
            confname.append(i.strip())
        f.close()
        print(confname)
        cmd = None
        for i in range(0,255):
            newname="IPADDR"+str(i)
            if newname not in confname:
                mask = inttoip(~((1 << (32 - prefix)) - 1))
                cmd = 'echo -e "IPADDR%d=%s\\nNETMASK%d=%s" >> /etc/sysconfig/network-scripts/ifcfg-lo:nat' % (i, ip, i, mask)
                os.system(cmd)
                break
        if not cmd:
            print("too many ip, exit")
            lockf.close()
            sys.exit(2)

    def setup(self):
        smp.assign_all()
        src = self.outlink.src_list()
        gwlist = self.outlink.gw_list()
        gwall = self.outlink.gw_all()
        ips = get_ip_addr()
        #ifcfg = ifcfg_handle("lo:nat")
        for s in src:
            #ifcfg.add_addr(s, 32)
            if s in ips:
                continue
            cmd="ip addr add dev lo %s/32" % (s)
            os.system(cmd)

     
        #ifcfg.apply()
        #get default gateway's macaddr
        #f = os.popen('ip route')
        #lines = []
        #tmp_line = ''
        #for line in f:
        #    if line[0] != '\t' and tmp_line != '':
        #        lines.append(tmp_line)
        #        tmp_line = line.strip('\n ')
        #    else:
        #        tmp_line += line.strip('\n ').replace('\t', ' ')
        #if tmp_line != '':
        #    lines.append(tmp_line)
        #f.close()
        #default_rt = None
        #for line in lines:
        #    default_rt = jz_route(line)
        #    if default_rt.addr == 'default':
        #        break
        default_rt = get_default_route()

        if not default_rt:
            print('can not found default route')
            lockf.close()
            sys.exit(-1)

        macs = []
        for hop in default_rt.hops:
            f = os.popen("arp -n %s | grep ether | awk '{print $3}'" % (hop.gw))
            for i in f:
                mac = i.strip()
            f.close()
            macs.append(mac)

        if len(macs) != len(default_rt.hops):
            print('can not get default gateway mac')
            lockf.close()
            sys.exit()

        #f = os.popen("ip route | grep default | cut -d' ' -f3 | xargs arp -n | grep ether | awk '{print $3}'")
        #for i in f:
        #    mac = i.strip()
        #f.close()

        #f = os.popen("ip route | grep default")
        #for i in f:
        #    ct = i.strip().split()
        #    for i in range(len(ct)):
        #        if ct[i] == "dev":
        #            default_dev = ct[i+1]
        #            break
        #f.close()

        sys_arp = {}
        f = os.popen("arp -n")
        for i in f:
            ct = i.strip().split()
            if len(ct) != 5:
                continue
            sys_arp[ct[0]] = ct[2]
        f.close()

        #arp_conf = {}
        #f = open("/etc/ethers","r")
        #for i in f:
        #    if i[0] == "#":
        #        continue
        #    ct = i.strip().split()
        #    arp_conf[ct[1]] = ct[0]
        #f.close()

        #ifcfg.add_addr("30.0.1.1", 26)
        #if "30.0.1.1" not in ips:
            #print("ip addr add dev %s 30.0.1.1/26" % (default_dev))
            #os.system("ip addr add dev %s 30.0.1.1/26" % (default_dev))
        idx=1
        for hop in default_rt.hops:
            gw="30.0.1.%d" % (idx)
            idx += 1
            if gw in gwall:
                print("error:%s should assign to %s, but now it's in outlink's gw"%(gw, hop.dev))
                lockf.close()
                sys.exit()
            if gw not in ips:
                print("ip addr add dev %s %s/24" % (hop.dev, gw))
                os.system("ip addr add dev %s %s/24" % (hop.dev, gw))

        hops = len(default_rt.hops)
        for tg in gwlist:
            for i in range(len(tg)):
                g = tg[i]
                if g.find("30.0.1") != 0:
                    continue
                if g not in sys_arp:
                    j = i
                    while j >= hops:
                        j = j - hops
                    cmd = "arp -i %s -s %s %s" % (default_rt.hops[j].dev, g, macs[j])
                    os.system(cmd)
                    print(cmd)
                #if g not in arp_conf:
                #    cmd = 'echo -e "%s\\t%s" >> /etc/ethers' % (mac, g)
                #os.system(cmd)
        #sys.exit()
        
        cmd = 'modprobe nf_nat_pptp &> /dev/null'
        os.system(cmd)

        cmd = 'echo 7200 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established'
        os.system(cmd)
                
def do_proc():
    jz = jznat()
    jz.load('jznat.conf')
    if auto_yes:
        jz.apply(False)
    else:
        jz.show()
        jz.apply()

def do_show():
    jz = jznat()
    jz.load('jznat.conf')
    jz.show()

def do_setup():
    jz = jznat()
    jz.load('jznat.conf')
    jz.setup()

def do_switch(conf_file, table, dst, out):
    if not conf_file or not table or not dst or not out:
        print("error, jznat --switch --file conf_file --table table --dst dst --via out")
        return
    try:
       	f = open(conf_file, 'r')
       	var = json.load(f)
       	f.close()
    except Exception,e:
        print("load %s error:%s" % (conf_file, str(e)))
        lockf.close()
        sys.exit(1)
    if not type(var) is dict:
        print("load %s error:not table dict" % (conf_file))
        lockf.close()
        sys.exit(1)
    newline = "%s via %s" % (dst, out)
    if table in var:
        found = False
        for i in var[table]:
            ct = i.split()
            if ct[0] == dst:
                 index = var[table].index(i)
                 del(var[table][index])
                 var[table].insert(index, newline)
                 found = True
                 break
        if not found:
            var[table].append(newline) 
    print(json.dumps(var, sort_keys=True, indent=4))

if __name__ == "__main__":
    force_main_default = False
    auto_yes = False
    cmd = None
    table = None
    dst = None
    out = None
    conf_file = None

    if not os.path.exists(lockfile):
        f = open(lockfile, 'w')
        f.write('jznat')
        f.close()

    try:
        lockf = open(lockfile, 'r+')
        fcntl.lockf(lockf, fcntl.LOCK_EX|fcntl.LOCK_NB)
    except Exception, e:
        lockf.close()
        print('error, maybe another process is running')
        sys.exit(-1)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'sfy', ["setup","show","force","switch","notcp","nopersistent","random","iptopt=","table=","dst=","via=","file="])
    except getopt.GetoptError as err:
        print(str(err))
        lockf.close()
        sys.exit(2)
    load_kernel_rules()
    for o, a in opts:
        if o in ("-s", "--setup"):
            do_setup()
            lockf.close()
            sys.exit()
        elif o in ("--show"):
            cmd = "show"
        elif o in ("-f", "--force"):
            force_main_default = True
        elif o in ("-y"):
            auto_yes = True
        elif o in ("--switch"):
            cmd = "switch"
        elif o in ("--table"):
            table = a
        elif o in ("--dst"):
            dst = a
        elif o in ("--via"):
            out = a
        elif o in ("--file"):
            conf_file = a
        elif o in ("--notcp"):
            none_tcp = True
        elif o in ("--iptopt"):
            ipt_opts = a
        elif o in ("--nopersistent"):
            nopersistent = True
        elif o in ("--random"):
            ipt_random = True

    try:
        if cmd == "switch":
            do_switch(conf_file, table, dst, out)
            lockf.close()
            sys.exit()
        elif cmd == "show":
            do_show()
            lockf.close()
            sys.exit()

        do_proc()
    except Exception,e:
        lockf.close()
        print(e)
        sys.exit(-1)
    else:
        lockf.close()
        sys.exit()


