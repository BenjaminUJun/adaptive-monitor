import pcap
import dpkt
import multiprocessing
import time
import traceback
import atexit
import signal
import sys
import commands
import logging


class sendData(multiprocessing.Process):
    def __init__(self, dict_f, interval, outfilepre, myblock):
        multiprocessing.Process.__init__(self)

        logging.log(logging.INFO, "")

        self.li_flow_count = dict_f
        self.interval = interval
        self.outfilepre = outfilepre
        self.myblock = myblock
        self.threadalive = True

    def run(self):
        while self.threadalive:
            self.myblock.acquire()
            count_length = len(self.li_flow_count)
            self.myblock.release()
            if count_length > 1:
                self.myblock.acquire()
                # copy works as well as deepcopy since int, string(for pktcountslot) and tuple int are unchangable
                flow_count_f = self.li_flow_count.copy()
                self.li_flow_count.clear()
                self.li_flow_count["pktcountslot"] = 0
                self.myblock.release()
                count_slot = flow_count_f["pktcountslot"]
                del flow_count_f["pktcountslot"]
                ''' replace the following part with curl request'''
                outfile = "./" + self.outfilepre + time.strftime("%Y-%m-%d-%H-%M-%S")
                out = open(outfile, 'w')
                out.write("# of flows = " + str(len(flow_count_f)) + "\n# of packets = " + str(count_slot) + "\n")
                sorted_flow_count = sorted(flow_count_f.iteritems(), key=lambda asd: asd[1], reverse=True)
                rest_str = '{' + '"' + sorted_flow_count[0][0][0] + '-' + sorted_flow_count[0][0][1] + '":' + str(
                    sorted_flow_count[0][1]) + ''.join(
                    ', "' + obj[0][0] + '-' + obj[0][1] + '":' + str(obj[1]) for obj in sorted_flow_count[1:]) + '}'
                print "rest_str =", rest_str
                cmd = "curl -X PUT -d '%s' http://10.1.0.122:8080/simpleswitch/statinfo/5e3e089e01a7de53" % rest_str
                print cmd
                (status, output) = commands.getstatusoutput(cmd)
                print "status =", status
                print "output =", output
                for obj in sorted_flow_count:
                    out.write(obj[0][0] + " " + obj[0][1] + " " + str(obj[1]) + "\n")
                out.write("\n")
                out.close()
            time.sleep(self.interval)

    def stop(self):
        self.threadalive = False


class listenInterface(multiprocessing.Process):
    def __init__(self, interface, dict_f, myblock):
        multiprocessing.Process.__init__(self)
        self.interface = interface
        self.packetscount = 0
        self.packetscountslot = 0
        self.flow_count = dict_f
        self.pc = None
        self.myblock = myblock
        self.process_alive = True

    def run(self):
        self.startListen()

    def startListen(self):
        print "start capturing %s . . ." % self.interface
        try:
            self.pc = pcap.pcap(self.interface)
        except Exception as ex:
            print "\n[ERROR]Failed to listen the interface!"
            traceback.print_exc()
            return
        for ts, pkt in self.pc:
            if not self.process_alive:
                return
            #            print pkt
            self.packetscount = self.packetscount + 1
            print "\rpackets captured = %d" % self.packetscount,
            sys.stdout.flush()
            p = dpkt.ethernet.Ethernet(pkt)
            if p == None:
                continue
            if p.data == None:
                continue
            if hasattr(p.data, "src"):
                src = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.src)))
            else:
                src = "256.256.256.256"
            if hasattr(p.data, "dst"):
                dst = '%d.%d.%d.%d' % tuple(map(ord, list(p.data.dst)))
            else:
                dst = "256.256.256.256"
            if hasattr(p.data, "data"):
                if hasattr(p.data.data, "sport"):
                    sport = p.data.data.sport
                else:
                    sport = -1
                if hasattr(p.data.data, "dport"):
                    dport = p.data.data.dport
                else:
                    dport = -1
            self.myblock.acquire()
            if (src, dst) in self.flow_count:
                self.flow_count[(src, dst)] = self.flow_count[(src, dst)] + 1
            else:
                self.flow_count[(src, dst)] = 1
#            self.flow_count[(src, dst)] = self.flow_count[(src, dst)] + 1 if (src, dst) in self.flow_count else 1
            self.flow_count["pktcountslot"] += 1
            #print "length = %d" % len(self.flow_count)
            self.myblock.release()

    def stop(self):
        self.process_alive = False


class ListenController(multiprocessing.Process):
    def init(self):
        multiprocessing.Process.__init__(self)
        self.listen_instance = None
        self.send_instance = None

    def run(self):
        try:
            mgr = multiprocessing.Manager()
            dict_f = mgr.dict()
            dict_f["pktcountslot"] = 0
            my_block = multiprocessing.RLock()
            self.listen_instance = listenInterface("eth1", dict_f, my_block)
            self.listen_instance.start()
            self.send_instance = sendData(dict_f, 3, "output", my_block)
            self.send_instance.start()
            self.listen_instance.join()
            self.send_instance.join()
            self.listen_instance.stop()
            self.send_instance.stop()
        except Exception, ex:
            print "failed"
            print ex
            return

    def kill_all(self):
        self.listen_instance.terminate()
        self.send_instance.terminate()


def _exit_clean():
    listen.kill_all()
    listen.terminate()


global listen
if __name__ == "__main__":
    global listen
    signal.signal(signal.SIGINT, _exit_clean)
    signal.signal(signal.SIGTERM, _exit_clean)
    try:
        listen = ListenController()
        listen.start()
        atexit.register(_exit_clean)
        listen.join()
    except Exception as ex:
        print "out from listen:"
        listen.terminate()
