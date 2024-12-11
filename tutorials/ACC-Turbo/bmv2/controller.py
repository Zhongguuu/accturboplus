# Runs with Python2

from __future__ import print_function
import time
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper
from time import sleep
import sys
import csv
import schedule
import grpc

class Controller:

    def __init__(self, p4info_file_path, bmv2_file_path):
        self.p4info_helper = P4InfoHelper(p4info_file_path)
        self.switch = self.p4info_helper.build_switch_connection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt'
        )
        self.switch.MasterArbitrationUpdate()
        self.switch.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)

        self.num_clusters = 4
        self.feature_list = ["dst0", "dst1", "dst2", "dst3"]
        self.init = True

        self.enable_logging_clusters = True
        self.enable_logging_priorities = True
        self.enable_logging_cluster_counters = True

        self.measure_throughput = True
        self.read_throughput_time = 9
        self.enable_logging_throughput = False

        if self.measure_throughput:
            self.file_throughput_benign = open("accturbo_throughput_benign.dat", "w")
            self.file_throughput_benign.write("# Timestamp(ns),Bits\n")
            self.file_throughput_malicious = open("accturbo_throughput_malicious.dat", "w")
            self.file_throughput_malicious.write("# Timestamp(ns),Bits\n")
            self.first_pass = True

        self.cluster_list = []
        self.setup_clusters()

    def setup_clusters(self):
        entries = self.switch.ReadTableEntries(self.p4info_helper.get_tables_id("MyIngress.cluster_to_prio"))
        for entry in entries:
            cluster_id = entry.match[0].exact.value
            current_priority = entry.action.params[0].value
            if self.enable_logging_priorities:
                print("(Read) cluster_to_prio ==> cluster_id {}, current_priority {}".format(cluster_id, current_priority))
            new_cluster = Cluster({}, cluster_id, current_priority, self.feature_list)
            self.cluster_list.append(new_cluster)

    def read_cluster_statistics_and_update_priorities(self):
        for cluster_id in range(1, self.num_clusters + 1):
            for feature in self.feature_list:
                min_reg_name = "MyIngress.cluster{}_{}_min".format(cluster_id, feature)
                max_reg_name = "MyIngress.cluster{}_{}_max".format(cluster_id, feature)
                min_value = self.read_register(min_reg_name)
                max_value = self.read_register(max_reg_name)
                if self.enable_logging_clusters:
                    print("(Read) cluster{}_{} [min, max] ==> [{}, {}]".format(cluster_id, feature, min_value, max_value))

        entries = self.switch.ReadTableEntries(self.p4info_helper.get_tables_id("MyIngress.do_bytes_count"))
        for entry in entries:
            qid = entry.match[0].exact.value
            counter_value = entry.counter_data.byte_count
            for cluster in self.cluster_list:
                if cluster.get_priority() == qid:
                    cluster.update_bytes_count(counter_value)
                    if self.enable_logging_cluster_counters:
                        print("(Read) do_bytes_count ==> cluster_id {}, counter_value {}".format(cluster.get_id(), counter_value))

        clusters_by_throughput = {i: cluster.get_bytes() for i, cluster in enumerate(self.cluster_list)}
        clusters_by_throughput = sorted(clusters_by_throughput.items(), key=lambda item: item[1])
        prio = self.num_clusters - 1
        for idx, _ in clusters_by_throughput:
            self.cluster_list[idx].set_priority(prio)
            prio -= 1

        for cluster in self.cluster_list:
            self.switch.WriteTableEntry(
                table_name="MyIngress.cluster_to_prio",
                match_fields={"meta.rs.cluster_id": cluster.get_id()},
                action_name="MyIngress.set_qid",
                action_params={"qid": cluster.get_priority()}
            )
            if self.enable_logging_priorities:
                print("(Write: New priorities) cluster_to_prio <== cluster_id {}, new_assigned_priority {}".format(cluster.get_id(), cluster.get_priority()))

        for qid in range(self.num_clusters):
            self.switch.ClearCounterBytes("MyIngress.do_bytes_count", "queue_id", qid)

    def read_register(self, register_name):
        entries = self.switch.ReadRegister(self.p4info_helper.get_registers_id(register_name))
        for entry in entries:
            return entry.data.uint64

    def reset_clusters_and_clear_counters(self):
        if self.init:
            for cluster_id in range(1, self.num_clusters + 1):
                for feature in self.feature_list:
                    self.switch.WriteRegister("MyIngress.cluster{}_{}_min".format(cluster_id, feature), 255)
                    self.switch.WriteRegister("MyIngress.cluster{}_{}_max".format(cluster_id, feature), 0)
        else:
            # Custom initialization logic
            pass

        self.switch.WriteRegister("MyIngress.init_counter", 1)
        self.switch.WriteRegister("MyIngress.updateclusters_counter", 0)

        for qid in range(self.num_clusters):
            self.switch.ClearCounterBytes("MyIngress.do_bytes_count", "queue_id", qid)

    def read_throughput(self):
        print("read_throughput")
        read_timestamp = self.read_register("MyEgress.timestamp") << 16

        entries = self.switch.ReadTableEntries(self.p4info_helper.get_tables_id("MyEgress.do_bytes_count_malicious_egress"))
        count_malicious_bits = sum(entry.counter_data.byte_count for entry in entries) * 8

        entries = self.switch.ReadTableEntries(self.p4info_helper.get_tables_id("MyEgress.do_bytes_count_benign_egress"))
        count_benign_bits = sum(entry.counter_data.byte_count for entry in entries) * 8

        if count_malicious_bits > 0 or count_benign_bits > 0:
            if self.first_pass:
                self.initial_timestamp = read_timestamp
                self.relative_timestamp = 0
                relative_count_malicious_bits = count_malicious_bits
                relative_count_benign_bits = count_benign_bits
                self.first_pass = False
            else:
                self.relative_timestamp = read_timestamp - self.initial_timestamp
                relative_count_malicious_bits = count_malicious_bits - self.last_count_malicious_bits
                relative_count_benign_bits = count_benign_bits - self.last_count_benign_bits

            self.file_throughput_malicious.write("{},{}\n".format(self.relative_timestamp, relative_count_malicious_bits))
            self.file_throughput_benign.write("{},{}\n".format(self.relative_timestamp, relative_count_benign_bits))

            self.last_count_malicious_bits = count_malicious_bits
            self.last_count_benign_bits = count_benign_bits

    def run(self):
        schedule.every(self.read_cluster_statistics_and_update_priorities_time).seconds.do(self.read_cluster_statistics_and_update_priorities)
        if self.measure_throughput:
            schedule.every(self.read_throughput_time).seconds.do(self.read_throughput)

        while True:
            schedule.run_pending()
            time.sleep(1)

        if self.measure_throughput:
            self.file_throughput_benign.close()
            self.file_throughput_malicious.close()

        self.switch.TearDown()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=True)
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=True)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: {}\nHave you run 'make'?".format(args.p4info))
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: {}\nHave you run 'make'?".format(args.bmv2_json))
        parser.exit(1)

    controller = Controller(args.p4info, args.bmv2_json)
    controller.run()