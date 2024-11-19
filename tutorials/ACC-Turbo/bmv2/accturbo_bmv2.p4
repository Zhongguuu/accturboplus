/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/

#define NUM_EGRESS_PORTS    512
#define NUM_CLUSTERS        4
#define PORT_METADATA_SIZE  8
#define PORT_ID_WIDTH                  9
//typedef bit<PORT_ID_WIDTH>             PortId_t;            // Port id -- ingress or egress port
#define MULTICAST_GROUP_ID_WIDTH       16
typedef bit<MULTICAST_GROUP_ID_WIDTH>  MulticastGroupId_t;  // Multicast group id
#define QUEUE_ID_WIDTH                 5
typedef bit<QUEUE_ID_WIDTH>            QueueId_t;           // Queue id
#define MIRROR_TYPE_WIDTH              3
typedef bit<MIRROR_TYPE_WIDTH>         MirrorType_t;        // Mirror type
#define MIRROR_ID_WIDTH                10
typedef bit<MIRROR_ID_WIDTH>           MirrorId_t;          // Mirror id
#define RESUBMIT_TYPE_WIDTH            3
typedef bit<RESUBMIT_TYPE_WIDTH>       ResubmitType_t;      // Resubmit type
#define DIGEST_TYPE_WIDTH              3
typedef bit<DIGEST_TYPE_WIDTH>         DigestType_t;        // Digest type
#define REPLICATION_ID_WIDTH           16
typedef bit<REPLICATION_ID_WIDTH>      ReplicationId_t;     // Replication id
#define L1_EXCLUSION_ID_WIDTH          16
typedef bit<L1_EXCLUSION_ID_WIDTH>     L1ExclusionId_t;     // L1 Exclusion id
#define L2_EXCLUSION_ID_WIDTH          9
typedef bit<L2_EXCLUSION_ID_WIDTH>     L2ExclusionId_t;     // L2 Exclusion id
// extern resubmit {
//     /// Constructor
//     @deprecated("Resubmit must be specified with the value of the resubmit_type instrinsic metadata")
//     Resubmit();

//     /// Constructor
//     Resubmit(ResubmitType_t resubmit_type);

//     /// Resubmit the packet.
//     void emit();

//     /// Resubmit the packet and prepend it with @hdr.
//     /// @param hdr : T can be a header type.
//     void emit<T>(in T hdr);
// }
/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
enum CounterType_t {
    PACKETS,
    BYTES,
    PACKETS_AND_BYTES
}
header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> len;
    bit<16> id;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<8> dst0;
    bit<8> dst1;
    bit<8> dst2;
    bit<8> dst3;
}

header transport_h {
    bit<16> sport;
    bit<16> dport;
}

struct resubmit_h1 {
    bit<8> cluster_id;
    bit<8> update_activated;
}

struct metadata {
    bit<8> cluster_id;
    bit<8> update_activated;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
header ipv4_egress_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> len;
    bit<16> id;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}
/* All the headers we plan to process in the ingress */
struct my_ingress_headers_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    transport_h  transport;
    ipv4_egress_h ipv4_egress;
}

/* All intermediate results that need to be available 
 * to all P4-programmable components in ingress
 */
struct my_ingress_metadata_t { // We will have to initialize them
    resubmit_h1 rs;

    /* Cluster 1 */
    bit<32> cluster1_dst0_distance;  
    bit<32> cluster1_dst1_distance;
    bit<32> cluster1_dst2_distance;
    bit<32> cluster1_dst3_distance;

    /* Cluster 2 */
    bit<32> cluster2_dst0_distance;  
    bit<32> cluster2_dst1_distance;
    bit<32> cluster2_dst2_distance;
    bit<32> cluster2_dst3_distance;

    /* Cluster 3 */
    bit<32> cluster3_dst0_distance;  
    bit<32> cluster3_dst1_distance;
    bit<32> cluster3_dst2_distance;
    bit<32> cluster3_dst3_distance;

    /* Cluster 4 */
    bit<32> cluster4_dst0_distance;  
    bit<32> cluster4_dst1_distance;
    bit<32> cluster4_dst2_distance;
    bit<32> cluster4_dst3_distance;

    // Distance helpers
    bit<32> min_d1_d2;
    bit<32> min_d3_d4;
    bit<32> min_d1_d2_d3_d4;
    
    // Initialization
    bit<8> init_counter_value;
}
header ingress_intrinsic_metadata_t {
    bit<1> resubmit_flag;               // Flag distinguishing original packets
                                        // from resubmitted packets.
    @padding bit<1> _pad1;

    bit<2> packet_version;              // Read-only Packet version.

    @padding bit<(4 - PORT_ID_WIDTH % 8)> _pad2;

    PortId_t ingress_port;              // Ingress physical port id.

    bit<48> ingress_mac_tstamp;         // Ingress IEEE 1588 timestamp (in nsec)
                                        // taken at the ingress MAC.
}
struct ingress_intrinsic_metadata_for_tm_t {
    PortId_t ucast_egress_port;         // Egress port for unicast packets. must
                                        // be presented to TM for unicast.

    bit<1> bypass_egress;               // Request flag for the warp mode
                                        // (egress bypass).

    bit<1> deflect_on_drop;             // Request for deflect on drop. must be
                                        // presented to TM to enable deflection
                                        // upon drop.

    bit<3> ingress_cos;                 // Ingress cos (iCoS) for PG mapping,
                                        // ingress admission control, PFC,
                                        // etc.

    QueueId_t qid;                      // Egress (logical) queue id into which
                                        // this packet will be deposited.

    bit<3> icos_for_copy_to_cpu;        // Ingress cos for the copy to CPU. must
                                        // be presented to TM if copy_to_cpu ==
                                        // 1.

    bit<1> copy_to_cpu;                 // Request for copy to cpu.

    bit<2> packet_color;                // Packet color (G,Y,R) that is
                                        // typically derived from meters and
                                        // used for color-based tail dropping.

    bit<1> disable_ucast_cutthru;       // Disable cut-through forwarding for
                                        // unicast.

    bit<1> enable_mcast_cutthru;        // Enable cut-through forwarding for
                                        // multicast.

    MulticastGroupId_t mcast_grp_a;     // 1st multicast group (i.e., tree) id;
                                        // a tree can have two levels. must be
                                        // presented to TM for multicast.

    MulticastGroupId_t mcast_grp_b;     // 2nd multicast group (i.e., tree) id;
                                        // a tree can have two levels.

    bit<13> level1_mcast_hash;          // Source of entropy for multicast
                                        // replication-tree level1 (i.e., L3
                                        // replication). must be presented to TM
                                        // for L3 dynamic member selection
                                        // (e.g., ECMP) for multicast.

    bit<13> level2_mcast_hash;          // Source of entropy for multicast
                                        // replication-tree level2 (i.e., L2
                                        // replication). must be presented to TM
                                        // for L2 dynamic member selection
                                        // (e.g., LAG) for nested multicast.

    L1ExclusionId_t level1_exclusion_id;  // Exclusion id for multicast
                                        // replication-tree level1. used for
                                        // pruning.

    L2ExclusionId_t level2_exclusion_id;  // Exclusion id for multicast
                                        // replication-tree level2. used for
                                        // pruning.

    bit<16> rid;                        // L3 replication id for multicast.
}
struct ingress_intrinsic_metadata_from_parser_t {
    bit<48> global_tstamp;              // Global timestamp (ns) taken upon
                                        // arrival at ingress.

    bit<32> global_ver;                 // Global version number taken upon
                                        // arrival at ingress.

    bit<16> parser_err;                 // Error flags indicating error(s)
                                        // encountered at ingress parser.
}
struct ingress_intrinsic_metadata_for_deparser_t {

    bit<3> drop_ctl;                    // Disable packet replication:
                                        //    - bit 0 disables unicast,
                                        //      multicast, and resubmit
                                        //    - bit 1 disables copy-to-cpu
                                        //    - bit 2 reserved
    DigestType_t digest_type;

    ResubmitType_t resubmit_type;

    MirrorType_t mirror_type;           // The user-selected mirror field list
                                        // index.
}
header egress_intrinsic_metadata_t {
    @padding bit<(8 - PORT_ID_WIDTH % 8)> _pad0;

    PortId_t egress_port;               // Egress port id.
                                        // this field is passed to the deparser

    @padding bit<5> _pad1;

    bit<19> enq_qdepth;                 // Queue depth at the packet enqueue
                                        // time.

    @padding bit<6> _pad2;

    bit<2> enq_congest_stat;            // Queue congestion status at the packet
                                        // enqueue time.

    @padding bit<14> _pad3;
    bit<18> enq_tstamp;                 // Time snapshot taken when the packet
                                        // is enqueued (in nsec).

    @padding bit<5> _pad4;

    bit<19> deq_qdepth;                 // Queue depth at the packet dequeue
                                        // time.

    @padding bit<6> _pad5;

    bit<2> deq_congest_stat;            // Queue congestion status at the packet
                                        // dequeue time.

    bit<8> app_pool_congest_stat;       // Dequeue-time application-pool
                                        // congestion status. 2bits per
                                        // pool.

    @padding bit<14> _pad6;
    bit<18> deq_timedelta;              // Time delta between the packet's
                                        // enqueue and dequeue time.

    bit<16> egress_rid;                 // L3 replication id for multicast
                                        // packets.

    @padding bit<7> _pad7;

    bit<1> egress_rid_first;            // Flag indicating the first replica for
                                        // the given multicast group.

    @padding bit<(8 - QUEUE_ID_WIDTH % 8)> _pad8;

    QueueId_t egress_qid;               // Egress (physical) queue id via which
                                        // this packet was served.

    @padding bit<5> _pad9;

    bit<3> egress_cos;                  // Egress cos (eCoS) value.

    @padding bit<7> _pad10;

    bit<1> deflection_flag;             // Flag indicating whether a packet is
                                        // deflected due to deflect_on_drop.

    bit<16> pkt_length;                 // Packet length, in bytes
}


struct egress_intrinsic_metadata_from_parser_t {
    bit<48> global_tstamp;              // Global timestamp (ns) taken upon
                                        // arrival at egress.

    bit<32> global_ver;                 // Global version number taken upon
                                        // arrival at ingress.

    bit<16> parser_err;                 // Error flags indicating error(s)
                                        // encountered at ingress parser.
}


struct egress_intrinsic_metadata_for_deparser_t {
    bit<3> drop_ctl;                    // Disable packet replication:
                                        //    - bit 0 disables unicast,
                                        //      multicast, and resubmit
                                        //    - bit 1 disables copy-to-cpu
                                        //    - bit 2 disables mirroring

    MirrorType_t mirror_type;

    bit<1> coalesce_flush;              // Flush the coalesced mirror buffer

    bit<7> coalesce_length;             // The number of bytes in the current
                                        // packet to collect in the mirror
                                        // buffer
}


struct egress_intrinsic_metadata_for_output_port_t {
    bit<1> capture_tstamp_on_tx;        // Request for packet departure
                                        // timestamping at egress MAC for IEEE
                                        // 1588. consumed by h/w (egress MAC).

    bit<1> update_delay_on_tx;          // Request for PTP delay (elapsed time)
                                        // update at egress MAC for IEEE 1588
                                        // Transparent Clock. consumed by h/w
                                        // (egress MAC). when this is enabled,
                                        // the egress pipeline must prepend a
                                        // custom header composed of <ingress
                                        // tstamp (40), byte offset for the
                                        // elapsed time field (8), byte offset
                                        // for UDP checksum (8)> in front of the
                                        // Ethernet header.
}
//TODO:
parser MyParser(packet_in                pkt,
    out my_ingress_headers_t                    hdr, 
    inout my_ingress_metadata_t                   meta, 
    inout standard_metadata_t            ig_intr_md) {

    state start {
        
        /* Mandatory code required by Tofino Architecture */
        //pkt.extract(ig_intr_md);

        /* We hardcode the egress port (all packets towards port 140) */
        ig_intr_md.egress_port = 140;

        /* Cluster 1 */
        meta.cluster1_dst0_distance = 0;
        meta.cluster1_dst1_distance = 0;
        meta.cluster1_dst2_distance = 0;
        meta.cluster1_dst3_distance = 0;

        /* Cluster 2 */
        meta.cluster2_dst0_distance = 0;
        meta.cluster2_dst1_distance = 0;
        meta.cluster2_dst2_distance = 0;
        meta.cluster2_dst3_distance = 0;

        /* Cluster 3 */
        meta.cluster3_dst0_distance = 0;
        meta.cluster3_dst1_distance = 0;
        meta.cluster3_dst2_distance = 0;
        meta.cluster3_dst3_distance = 0;

        /* Cluster 4 */
        meta.cluster4_dst0_distance = 0;
        meta.cluster4_dst1_distance = 0;
        meta.cluster4_dst2_distance = 0;
        meta.cluster4_dst3_distance = 0;

        // Distance helpers
        meta.min_d1_d2 = 0;
        meta.min_d3_d4 = 0;
        meta.min_d1_d2_d3_d4 = 0;

        /* Parser start point */
        transition select(ig_intr_md.resubmit_flag) {
            0: parse_port_metadata;
            1: parse_resubmit;
        }
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_resubmit {
        //pkt.extract(meta.rs);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x0800:  parse_ipv4;
            default: accept;
        }
    }

    /* We only parse layer 4 if the packet is a first fragment (frag_offset == 0) and if ipv4 header contains no options (ihl == 5) */
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.proto, hdr.ipv4.ihl) {
            (0, 6, 5)  : parse_transport;
            (0, 17, 5) : parse_transport;
            default : accept;
        }
    }

    state parse_transport {
        pkt.extract(hdr.transport);
        transition accept;
    }
}
//TODO:修改使用的metadata部分
control MyVerifyChecksum(inout my_ingress_headers_t hdr, inout my_ingress_metadata_t meta) {
    apply {  }
}
control MyIngress(
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    inout    standard_metadata_t               ig_intr_md) {   

    /* Define variables, actions and tables here */
    action set_qid(QueueId_t qid) {
        ig_intr_md.qid = qid;
    }

    table cluster_to_prio {
        key = {
            meta.rs.cluster_id : exact;
        }
        actions = {
            set_qid;
        }
        default_action = set_qid(0); // Lowest-priority queue.
        size = NUM_CLUSTERS;
    }

    /****/
    /**** Clustering control registers */
    /****/

    /* Cluster 1 */
    /* IP dst0 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst0_min;
    action distance_cluster1_dst0_min(in PortId_t port,out bit<32> distance) {
        bit<32> data;
        cluster1_dst0_min.read(data, port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
    }

    action update_cluster1_dst0_min() {
        bit<32> data;
        cluster1_dst0_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster1_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }

    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst0_max;
    action distance_cluster1_dst0_max(out bit<32> distance) {
        bit<32> data;
        cluster1_dst0_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
    }

    action update_cluster1_dst0_max() {
        bit<32> data;
        cluster1_dst0_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster1_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst1 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst1_min;
    action distance_cluster1_dst1_min(out bit<32> distance) {
        bit<32> data;
        cluster1_dst1_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
    }
    action update_cluster1_dst1_min() {
        bit<32> data;
        cluster1_dst1_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster1_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }

    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst1_max;
    action distance_cluster1_dst1_max(out bit<32> distance) {
        bit<32> data;
        cluster1_dst1_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
    }
    action update_cluster1_dst1_max() {
        bit<32> data;
        cluster1_dst1_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster1_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst2 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst2_min;
    action distance_cluster1_dst2_min(out bit<32> distance) {
        bit<32> data;
        cluster1_dst2_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
    }
    action update_cluster1_dst2_min() {
        bit<32> data;
        cluster1_dst2_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster1_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst2_max;
    action distance_cluster1_dst2_max(out bit<32> distance) {
        bit<32> data;
        cluster1_dst2_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
    }
    action update_cluster1_dst2_max() {
        bit<32> data;
        cluster1_dst2_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster1_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst3 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst3_min;
    action distance_cluster1_dst3_min(out bit<32> distance) {
        bit<32> data;
        cluster1_dst3_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
    }
    action update_cluster1_dst3_min() {
        bit<32> data;
        cluster1_dst3_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster1_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster1_dst3_max;
    action distance_cluster1_dst3_max(out bit<32> distance) {
        bit<32> data;
        cluster1_dst3_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
    }
    action update_cluster1_dst3_max() {
        bit<32> data;
        cluster1_dst3_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster1_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* Cluster 2 */
    /* IP dst0 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst0_min;
    action distance_cluster2_dst0_min(out bit<32> distance) {
        bit<32> data;
        cluster2_dst0_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
    }
    action update_cluster2_dst0_min() {
        bit<32> data;
        cluster2_dst0_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster2_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst0_max;
    action distance_cluster2_dst0_max(out bit<32> distance) {
        bit<32> data;
        cluster2_dst0_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
    }
    action update_cluster2_dst0_max() {
        bit<32> data;
        cluster2_dst0_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster2_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst1 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst1_min;
    action distance_cluster2_dst1_min(out bit<32> distance) {
        bit<32> data;
        cluster2_dst1_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
    }
    action update_cluster2_dst1_min() {
        bit<32> data;
        cluster2_dst1_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster2_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst1_max;
    action distance_cluster2_dst1_max(out bit<32> distance) {
        bit<32> data;
        cluster2_dst1_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
    }
    action update_cluster2_dst1_max() {
        bit<32> data;
        cluster2_dst1_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster2_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst2 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst2_min;
    action distance_cluster2_dst2_min(out bit<32> distance) {
        bit<32> data;
        cluster2_dst2_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
    }
    action update_cluster2_dst2_min() {
        bit<32> data;
        cluster2_dst2_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster2_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst2_max;
    action distance_cluster2_dst2_max(out bit<32> distance) {
        bit<32> data;
        cluster2_dst2_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
    }
    action update_cluster2_dst2_max() {
        bit<32> data;
        cluster2_dst2_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster2_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst3 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst3_min;
    action distance_cluster2_dst3_min(out bit<32> distance) {
        bit<32> data;
        cluster2_dst3_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
    }   
    action update_cluster2_dst3_min() {
        bit<32> data;
        cluster2_dst3_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster2_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster2_dst3_max;
    action distance_cluster2_dst3_max(out bit<32> distance) {
        bit<32> data;
        cluster2_dst3_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
    }
    action update_cluster2_dst3_max() {
        bit<32> data;
        cluster2_dst3_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster2_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* Cluster 3 */
    /* IP dst0 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst0_min;
    action distance_cluster3_dst0_min(out bit<32> distance) {
        bit<32> data;
        cluster3_dst0_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
    }
    action update_cluster3_dst0_min() {
        bit<32> data;
        cluster3_dst0_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster3_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst0_max;
    action distance_cluster3_dst0_max(out bit<32> distance) {
        bit<32> data;
        cluster3_dst0_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
    }
    action update_cluster3_dst0_max() {
        bit<32> data;
        cluster3_dst0_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster3_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst1 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst1_min;
    action distance_cluster3_dst1_min(out bit<32> distance) {
        bit<32> data;
        cluster3_dst1_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
    }
    action update_cluster3_dst1_min() {
        bit<32> data;
        cluster3_dst1_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster3_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst1_max;
    action distance_cluster3_dst1_max(out bit<32> distance) {
        bit<32> data;
        cluster3_dst1_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
    }
    action update_cluster3_dst1_max() {
        bit<32> data;
        cluster3_dst1_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster3_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst2 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst2_min;
    action distance_cluster3_dst2_min(out bit<32> distance) {
        bit<32> data;
        cluster3_dst2_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
    }
    action update_cluster3_dst2_min() {
        bit<32> data;
        cluster3_dst2_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster3_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst2_max;
    action distance_cluster3_dst2_max(out bit<32> distance) {
        bit<32> data;
        cluster3_dst2_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
    }
    action update_cluster3_dst2_max() {
        bit<32> data;
        cluster3_dst2_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster3_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst3 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst3_min;
    action distance_cluster3_dst3_min(out bit<32> distance) {
        bit<32> data;
        cluster3_dst3_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
    }
    action update_cluster3_dst3_min() {
        bit<32> data;
        cluster3_dst3_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster3_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster3_dst3_max;
    action distance_cluster3_dst3_max(out bit<32> distance) {
        bit<32> data;
        cluster3_dst3_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
    }
    action update_cluster3_dst3_max() {
        bit<32> data;
        cluster3_dst3_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster3_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* Cluster 4 */
    /* IP dst0  */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst0_min;
    action distance_cluster4_dst0_min(out bit<32> distance) {
        bit<32> data;
        cluster4_dst0_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
    }
    action update_cluster4_dst0_min() {
        bit<32> data;
        cluster4_dst0_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster4_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst0_max;
    action distance_cluster4_dst0_max(out bit<32> distance) {
        bit<32> data;
        cluster4_dst0_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
    }
    action update_cluster4_dst0_max() {
        bit<32> data;
        cluster4_dst0_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster4_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst1 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst1_min;
    action distance_cluster4_dst1_min(out bit<32> distance) {
        bit<32> data;
        cluster4_dst1_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
    }
    action update_cluster4_dst1_min() {
        bit<32> data;
        cluster4_dst1_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster4_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst1_max;
    action distance_cluster4_dst1_max(out bit<32> distance) {
        bit<32> data;
        cluster4_dst1_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
    }
    action update_cluster4_dst1_max() {
        bit<32> data;
        cluster4_dst1_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster4_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst2 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst2_min;
    action distance_cluster4_dst2_min(out bit<32> distance) {
        bit<32> data;
        cluster4_dst2_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
    }
    action update_cluster4_dst2_min() {
        bit<32> data;
        cluster4_dst2_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster4_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst2_max;
    action distance_cluster4_dst2_max(out bit<32> distance) {
        bit<32> data;
        cluster4_dst2_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
    }
    action update_cluster4_dst2_max() {
        bit<32> data;
        cluster4_dst2_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster4_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /* IP dst3 */
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst3_min;
    action distance_cluster4_dst3_min(out bit<32> distance) {
        bit<32> data;
        cluster4_dst3_min.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
    }
    action update_cluster4_dst3_min() {
        bit<32> data;
        cluster4_dst3_min.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster4_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    register<bit<32>, PortId_t>(NUM_EGRESS_PORTS) cluster4_dst3_max;
    action distance_cluster4_dst3_max(out bit<32> distance) {
        bit<32> data;
        cluster4_dst3_max.read(data, ig_intr_md.egress_port);
        distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
    }
    action update_cluster4_dst3_max() {
        bit<32> data;
        cluster4_dst3_max.read(data, ig_intr_md.egress_port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster4_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    /****/
    /**** Actions to compute distances */
    /****/

    /* Cluster 1 */
    action compute_distance_cluster1_dst0_min(PortId_t port) {
        bit<32> data;
        cluster1_dst0_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
        meta.cluster1_dst0_distance = distance;
    }
    action compute_distance_cluster1_dst0_max(PortId_t port) {
        bit<32> data;
        cluster1_dst0_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
        meta.cluster1_dst0_distance = distance;
    }

    action compute_distance_cluster1_dst1_min(PortId_t port) {
        bit<32> data;
        cluster1_dst1_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
        meta.cluster1_dst1_distance = distance;
    }
    action compute_distance_cluster1_dst1_max(PortId_t port) {
        bit<32> data;
        cluster1_dst1_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
        meta.cluster1_dst1_distance = distance;
    }

    action compute_distance_cluster1_dst2_min(PortId_t port) {
        bit<32> data;
        cluster1_dst2_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
        meta.cluster1_dst2_distance = distance;
    }
    action compute_distance_cluster1_dst2_max(PortId_t port) {
        bit<32> data;
        cluster1_dst2_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
        meta.cluster1_dst2_distance = distance;
    }

    action compute_distance_cluster1_dst3_min(PortId_t port) {
        bit<32> data;
        cluster1_dst3_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
        meta.cluster1_dst3_distance = distance;
    }
    action compute_distance_cluster1_dst3_max(PortId_t port) {
        bit<32> data;
        cluster1_dst3_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
        meta.cluster1_dst3_distance = distance;
    }

    table tbl_compute_distance_cluster1_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst0_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster1_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst0_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster1_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst1_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    } 

    table tbl_compute_distance_cluster1_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst1_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster1_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst2_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    } 

    table tbl_compute_distance_cluster1_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst2_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster1_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst3_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    } 

    table tbl_compute_distance_cluster1_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster1_dst3_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    /* Cluster 2 */
    action compute_distance_cluster2_dst0_min(PortId_t port) {
        bit<32> data;
        cluster2_dst0_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
        meta.cluster2_dst0_distance = distance;
    }
    action compute_distance_cluster2_dst0_max(PortId_t port) {
        bit<32> data;
        cluster2_dst0_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
        meta.cluster2_dst0_distance = distance;
    }

    action compute_distance_cluster2_dst1_min(PortId_t port) {
        bit<32> data;
        cluster2_dst1_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
        meta.cluster2_dst1_distance = distance;
    }
    action compute_distance_cluster2_dst1_max(PortId_t port) {
        bit<32> data;
        cluster2_dst1_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
        meta.cluster2_dst1_distance = distance;
    }

    action compute_distance_cluster2_dst2_min(PortId_t port) {
        bit<32> data;
        cluster2_dst2_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
        meta.cluster2_dst2_distance = distance;
    }
    action compute_distance_cluster2_dst2_max(PortId_t port) {
        bit<32> data;
        cluster2_dst2_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
        meta.cluster2_dst2_distance = distance;
    }

    action compute_distance_cluster2_dst3_min(PortId_t port) {
        bit<32> data;
        cluster2_dst3_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
        meta.cluster2_dst3_distance = distance;
    }
    action compute_distance_cluster2_dst3_max(PortId_t port) {
        bit<32> data;
        cluster2_dst3_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
        meta.cluster2_dst3_distance = distance;
    }

    table tbl_compute_distance_cluster2_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst0_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    } 

    table tbl_compute_distance_cluster2_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst0_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster2_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst1_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster2_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst1_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster2_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst2_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster2_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst2_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster2_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst3_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    } 

    table tbl_compute_distance_cluster2_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster2_dst3_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    /* Cluster 3 */
    action compute_distance_cluster3_dst0_min(PortId_t port) {
        bit<32> data;
        cluster3_dst0_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
        meta.cluster3_dst0_distance = distance;
    }
    action compute_distance_cluster3_dst0_max(PortId_t port) {
        bit<32> data;
        cluster3_dst0_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
        meta.cluster3_dst0_distance = distance;
    }

    action compute_distance_cluster3_dst1_min(PortId_t port) {
        bit<32> data;
        cluster3_dst1_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
        meta.cluster3_dst1_distance = distance;
    }
    action compute_distance_cluster3_dst1_max(PortId_t port) {
        bit<32> data;
        cluster3_dst1_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
        meta.cluster3_dst1_distance = distance;
    }

    action compute_distance_cluster3_dst2_min(PortId_t port) {
        bit<32> data;
        cluster3_dst2_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
        meta.cluster3_dst2_distance = distance;
    }
    action compute_distance_cluster3_dst2_max(PortId_t port) {
        bit<32> data;
        cluster3_dst2_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
        meta.cluster3_dst2_distance = distance;
    }

    action compute_distance_cluster3_dst3_min(PortId_t port) {
        bit<32> data;
        cluster3_dst3_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
        meta.cluster3_dst3_distance = distance;
    }
    action compute_distance_cluster3_dst3_max(PortId_t port) {
        bit<32> data;
        cluster3_dst3_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
        meta.cluster3_dst3_distance = distance;
    }

    table tbl_compute_distance_cluster3_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst0_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster3_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst0_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster3_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst1_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster3_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst1_max;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster3_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst2_min;
            NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster3_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst2_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster3_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst3_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster3_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster3_dst3_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    /* Cluster 4 */
    action compute_distance_cluster4_dst0_min(PortId_t port) {
        bit<32> data;
        cluster4_dst0_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst0;
        }
        meta.cluster4_dst0_distance = distance;
    }
    action compute_distance_cluster4_dst0_max(PortId_t port) {
        bit<32> data;
        cluster4_dst0_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst0 > data) {
            distance = (bit<32>)hdr.ipv4.dst0 - data;
        }
        meta.cluster4_dst0_distance = distance;
    }

    action compute_distance_cluster4_dst1_min(PortId_t port) {
        bit<32> data;
        cluster4_dst1_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst1;
        }
        meta.cluster4_dst1_distance = distance;
    }
    action compute_distance_cluster4_dst1_max(PortId_t port) {
        bit<32> data;
        cluster4_dst1_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst1 > data) {
            distance = (bit<32>)hdr.ipv4.dst1 - data;
        }
        meta.cluster4_dst1_distance = distance;
    }

    action compute_distance_cluster4_dst2_min(PortId_t port) {
        bit<32> data;
        cluster4_dst2_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst2;
        }
        meta.cluster4_dst2_distance = distance;
    }
    action compute_distance_cluster4_dst2_max(PortId_t port) {
        bit<32> data;
        cluster4_dst2_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst2 > data) {
            distance = (bit<32>)hdr.ipv4.dst2 - data;
        }
        meta.cluster4_dst2_distance = distance;
    }

    action compute_distance_cluster4_dst3_min(PortId_t port) {
        bit<32> data;
        cluster4_dst3_min.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 < data) {
            distance = data - (bit<32>)hdr.ipv4.dst3;
        }
        meta.cluster4_dst3_distance = distance;
    }
    action compute_distance_cluster4_dst3_max(PortId_t port) {
        bit<32> data;
        cluster4_dst3_max.read(data, port);
        bit<32> distance = 0;
        if ((bit<32>)hdr.ipv4.dst3 > data) {
            distance = (bit<32>)hdr.ipv4.dst3 - data;
        }
        meta.cluster4_dst3_distance = distance;
    }

    table tbl_compute_distance_cluster4_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst0_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster4_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst0_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster4_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst1_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster4_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst1_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster4_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst2_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster4_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst2_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster4_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst3_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_compute_distance_cluster4_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            compute_distance_cluster4_dst3_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    /****/
    /**** Actions to merge distances and compute min distance */
    /****/

    // If we wanted to put dst1 in another PHV group to free PHV space
    //Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_1;
    //Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_2;
    //Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_3;
    //Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_4;

    //action merge_dst1_to_dst0_1_2() {
    //    meta.cluster1_dst0_distance = meta.cluster1_dst0_distance + copy_1.get(meta.cluster1_dst1_distance);
    //    meta.cluster2_dst0_distance = meta.cluster2_dst0_distance + copy_2.get(meta.cluster2_dst1_distance);
    //}

    //action merge_dst1_to_dst0_3_4() {
    //    meta.cluster3_dst0_distance = meta.cluster3_dst0_distance + copy_3.get(meta.cluster3_dst1_distance);
    //    meta.cluster4_dst0_distance = meta.cluster4_dst0_distance + copy_4.get(meta.cluster4_dst1_distance);
    //}

    action merge_dst1_to_dst0() {
        meta.cluster1_dst0_distance = meta.cluster1_dst0_distance + meta.cluster1_dst1_distance;
        meta.cluster2_dst0_distance = meta.cluster2_dst0_distance + meta.cluster2_dst1_distance;
        meta.cluster3_dst0_distance = meta.cluster3_dst0_distance + meta.cluster3_dst1_distance;
        meta.cluster4_dst0_distance = meta.cluster4_dst0_distance + meta.cluster4_dst1_distance;
    }

    action merge_dst2_to_dst0() {
        meta.cluster1_dst0_distance = meta.cluster1_dst0_distance + meta.cluster1_dst2_distance;
        meta.cluster2_dst0_distance = meta.cluster2_dst0_distance + meta.cluster2_dst2_distance;
        meta.cluster3_dst0_distance = meta.cluster3_dst0_distance + meta.cluster3_dst2_distance;
        meta.cluster4_dst0_distance = meta.cluster4_dst0_distance + meta.cluster4_dst2_distance;
    }

    action merge_dst3_to_dst0() {
        meta.cluster1_dst0_distance = meta.cluster1_dst0_distance + meta.cluster1_dst3_distance;
        meta.cluster2_dst0_distance = meta.cluster2_dst0_distance + meta.cluster2_dst3_distance;
        meta.cluster3_dst0_distance = meta.cluster3_dst0_distance + meta.cluster3_dst3_distance;
        meta.cluster4_dst0_distance = meta.cluster4_dst0_distance + meta.cluster4_dst3_distance;
    }

    action compute_min_first() {
        //meta.min_d1_d2 = min(meta.cluster1_dst0_distance, meta.cluster2_dst0_distance);
        //meta.min_d3_d4 = min(meta.cluster3_dst0_distance, meta.cluster4_dst0_distance);
        if(meta.cluster1_dst0_distance < meta.cluster2_dst0_distance) {
            meta.min_d1_d2 = meta.cluster1_dst0_distance;
        } else {
            meta.min_d1_d2 = meta.cluster2_dst0_distance;
        }
        if(meta.cluster3_dst0_distance < meta.cluster4_dst0_distance) {
            meta.min_d3_d4 = meta.cluster3_dst0_distance;
        } else {
            meta.min_d3_d4 = meta.cluster4_dst0_distance;
        }
    }

    action compute_min_second() {
        //meta.min_d1_d2_d3_d4 = min(meta.min_d1_d2, meta.min_d3_d4);
        if(meta.min_d1_d2 < meta.min_d3_d4) {
            meta.min_d1_d2_d3_d4 = meta.min_d1_d2;
        } else {
            meta.min_d1_d2_d3_d4 = meta.min_d3_d4;
        }
    }

    /****/
    /**** Actions to update ranges */
    /****/

    /* Cluster 1 */
    action do_update_cluster1_dst0_min(PortId_t port) {
        bit<32> data;
        cluster1_dst0_min.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster1_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster1_dst0_max(PortId_t port) {
        bit<32> data;
        cluster1_dst0_max.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster1_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster1_dst1_min(PortId_t port) {
        bit<32> data;
        cluster1_dst1_min.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster1_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster1_dst1_max(PortId_t port) {
        bit<32> data;
        cluster1_dst1_max.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster1_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster1_dst2_min(PortId_t port) {
        bit<32> data;
        cluster1_dst2_min.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster1_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster1_dst2_max(PortId_t port) {
        bit<32> data;
        cluster1_dst2_max.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster1_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster1_dst3_min(PortId_t port) {
        bit<32> data;
        cluster1_dst3_min.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster1_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster1_dst3_max(PortId_t port) {
        bit<32> data;
        cluster1_dst3_max.read(data, port);
        if (meta.rs.cluster_id == 1) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster1_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    table tbl_do_update_cluster1_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst0_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_do_update_cluster1_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst0_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_do_update_cluster1_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst1_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_do_update_cluster1_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst1_max;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    table tbl_do_update_cluster1_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst2_min;
            @defaultonly NoAction;
        }
        default_action = NoAction();
        size = 512;
    }

    @pragma stage 6
    table tbl_do_update_cluster1_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst2_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 3
    table tbl_do_update_cluster1_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst3_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 7
    table tbl_do_update_cluster1_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster1_dst3_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    /* Cluster 2 */
    action do_update_cluster2_dst0_min(PortId_t port) {
        bit<32> data;
        cluster2_dst0_min.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster2_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster2_dst0_max(PortId_t port) {
        bit<32> data;
        cluster2_dst0_max.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster2_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster2_dst1_min(PortId_t port) {
        bit<32> data;
        cluster2_dst1_min.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster2_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster2_dst1_max(PortId_t port) {
        bit<32> data;
        cluster2_dst1_max.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster2_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster2_dst2_min(PortId_t port) {
        bit<32> data;
        cluster2_dst2_min.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster2_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster2_dst2_max(PortId_t port) {
        bit<32> data;
        cluster2_dst2_max.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster2_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster2_dst3_min(PortId_t port) {
        bit<32> data;
        cluster2_dst3_min.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster2_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster2_dst3_max(PortId_t port) {
        bit<32> data;
        cluster2_dst3_max.read(data, port);
        if (meta.rs.cluster_id == 2) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster2_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    @pragma stage 0
    table tbl_do_update_cluster2_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst0_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 4
    table tbl_do_update_cluster2_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst0_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 1
    table tbl_do_update_cluster2_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst1_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 5
    table tbl_do_update_cluster2_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst1_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 2
    table tbl_do_update_cluster2_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst2_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 6
    table tbl_do_update_cluster2_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst2_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 3
    table tbl_do_update_cluster2_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst3_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 7
    table tbl_do_update_cluster2_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster2_dst3_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    /* Cluster 3 */
    action do_update_cluster3_dst0_min(PortId_t port) {
        bit<32> data;
        cluster3_dst0_min.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster3_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster3_dst0_max(PortId_t port) {
        bit<32> data;
        cluster3_dst0_max.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster3_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster3_dst1_min(PortId_t port) {
        bit<32> data;
        cluster3_dst1_min.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster3_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster3_dst1_max(PortId_t port) {
        bit<32> data;
        cluster3_dst1_max.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster3_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster3_dst2_min(PortId_t port) {
        bit<32> data;
        cluster3_dst2_min.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster3_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster3_dst2_max(PortId_t port) {
        bit<32> data;
        cluster3_dst2_max.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster3_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster3_dst3_min(PortId_t port) {
        bit<32> data;
        cluster3_dst3_min.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster3_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster3_dst3_max(PortId_t port) {
        bit<32> data;
        cluster3_dst3_max.read(data, port);
        if (meta.rs.cluster_id == 3) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster3_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    @pragma stage 0
    table tbl_do_update_cluster3_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst0_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 4
    table tbl_do_update_cluster3_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst0_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 1
    table tbl_do_update_cluster3_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst1_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 5
    table tbl_do_update_cluster3_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst1_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 2
    table tbl_do_update_cluster3_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst2_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 6
    table tbl_do_update_cluster3_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst2_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 3
    table tbl_do_update_cluster3_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst3_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 7
    table tbl_do_update_cluster3_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster3_dst3_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    /* Cluster 4 */
    action do_update_cluster4_dst0_min(PortId_t port) {
        bit<32> data;
        cluster4_dst0_min.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst0 < data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster4_dst0_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster4_dst0_max(PortId_t port) {
        bit<32> data;
        cluster4_dst0_max.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst0 > data) {
                data = (bit<32>)hdr.ipv4.dst0;
                cluster4_dst0_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster4_dst1_min(PortId_t port) {
        bit<32> data;
        cluster4_dst1_min.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst1 < data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster4_dst1_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster4_dst1_max(PortId_t port) {
        bit<32> data;
        cluster4_dst1_max.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst1 > data) {
                data = (bit<32>)hdr.ipv4.dst1;
                cluster4_dst1_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster4_dst2_min(PortId_t port) {
        bit<32> data;
        cluster4_dst2_min.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst2 < data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster4_dst2_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster4_dst2_max(PortId_t port) {
        bit<32> data;
        cluster4_dst2_max.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst2 > data) {
                data = (bit<32>)hdr.ipv4.dst2;
                cluster4_dst2_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    action do_update_cluster4_dst3_min(PortId_t port) {
        bit<32> data;
        cluster4_dst3_min.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst3 < data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster4_dst3_min.write(ig_intr_md.egress_port, data);
            }
        }
    }
    action do_update_cluster4_dst3_max(PortId_t port) {
        bit<32> data;
        cluster4_dst3_max.read(data, port);
        if (meta.rs.cluster_id == 4) {
            if ((bit<32>)hdr.ipv4.dst3 > data) {
                data = (bit<32>)hdr.ipv4.dst3;
                cluster4_dst3_max.write(ig_intr_md.egress_port, data);
            }
        }
    }

    @pragma stage 0
    table tbl_do_update_cluster4_dst0_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst0_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 4
    table tbl_do_update_cluster4_dst0_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst0_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 1
    table tbl_do_update_cluster4_dst1_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst1_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 5
    table tbl_do_update_cluster4_dst1_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst1_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 2
    table tbl_do_update_cluster4_dst2_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst2_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 6
    table tbl_do_update_cluster4_dst2_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst2_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 3
    table tbl_do_update_cluster4_dst3_min {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst3_min;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    @pragma stage 7
    table tbl_do_update_cluster4_dst3_max {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_update_cluster4_dst3_max;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    }

    /* Tables and actions to count the traffic of each cluster */
    direct_counter(CounterType.bytes) bytes_counter;

    action bytes_count() {
        bytes_counter.count();
    }

    table do_bytes_count {
        key = {
            ig_intr_md.qid: exact @name("queue_id");
        }
        actions = { 
            bytes_count; 
        }
        counters = bytes_counter;
        default_action = bytes_count();
        size = 32;
    }

    /* Register to be used as counter for cluster initialization */   

    
    register <bit<32>, PortId_t>(NUM_EGRESS_PORTS) init_counter;

    action do_init_counter(PortId_t port) {
        bit<32> data;
        init_counter.read(data, ig_intr_md.egress_port);
        bit<8> current_value = 0;
        if (data < (bit<32>)5) {
            current_value = (bit<8>)data;
        }
        data = data + 1;
        init_counter.write(ig_intr_md.egress_port, data);
        meta.init_counter_value = (bit<8>)data;
    }

    table tbl_do_init_counter {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_init_counter;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    } 

    /* Register to be used as counter to determine when to update clusters */
    register <bit<32>, PortId_t>(NUM_EGRESS_PORTS) updateclusters_counter;
    action updateclusters_count(out bit<8> current_value) {
        bit<32> data;
        updateclusters_counter.read(data, ig_intr_md.egress_port);
        current_value = 0;
        if (data < (bit<32>)10000000) {
            data = data + 1;
            current_value = (bit<8>)0;
        } else {
            data = 0;
            current_value = (bit<8>)1;
        }
        updateclusters_counter.write(ig_intr_md.egress_port, data);
    }

    action do_updateclusters_counter(PortId_t port) {
        bit<32> data;
        updateclusters_counter.read(data, ig_intr_md.egress_port);
        bit<8> current_value = 0;
        if (data < (bit<32>)10000000) {
            data = data + 1;
            current_value = (bit<8>)0;
        } else {
            data = 0;
            current_value = (bit<8>)1;
        }
        updateclusters_counter.write(ig_intr_md.egress_port, data);
    }

    table tbl_do_updateclusters_counter {
        key = {
            ig_intr_md.egress_port : exact;
        }
        actions = {
            do_updateclusters_counter;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = 512;
    } 

    /* Define the processing algorithm here */
            // Resubmit() do_resubmit;
    apply {


        // If all headers are valid and metadata ready, we run the clustering algorithm
        if (hdr.ipv4.isValid()) {

            if (ig_intr_md.resubmit_flag == 0){ 
                
                // Initial (non-resubmitted) packet

                /* Stage 0 */
                tbl_compute_distance_cluster1_dst0_min.apply();
                tbl_compute_distance_cluster2_dst0_min.apply();
                tbl_compute_distance_cluster3_dst0_min.apply();
                tbl_compute_distance_cluster4_dst0_min.apply();

                /* Stage 1 */
                tbl_compute_distance_cluster1_dst1_min.apply();
                tbl_compute_distance_cluster2_dst1_min.apply();
                tbl_compute_distance_cluster3_dst1_min.apply();
                tbl_compute_distance_cluster4_dst1_min.apply();

                /* Stage 2 */
                tbl_compute_distance_cluster1_dst2_min.apply();
                tbl_compute_distance_cluster2_dst2_min.apply();
                tbl_compute_distance_cluster3_dst2_min.apply();
                tbl_compute_distance_cluster4_dst2_min.apply();

                /* Stage 3 */
                tbl_compute_distance_cluster1_dst3_min.apply();
                tbl_compute_distance_cluster2_dst3_min.apply();
                tbl_compute_distance_cluster3_dst3_min.apply();
                tbl_compute_distance_cluster4_dst3_min.apply();

                /* Stage 4 */
                if (meta.cluster1_dst0_distance == 0) {
                    tbl_compute_distance_cluster1_dst0_max.apply();
                }
                if (meta.cluster2_dst0_distance == 0) {
                    tbl_compute_distance_cluster2_dst0_max.apply();
                }
                if (meta.cluster3_dst0_distance == 0) {
                    tbl_compute_distance_cluster3_dst0_max.apply();
                }
                if (meta.cluster4_dst0_distance == 0) {
                    tbl_compute_distance_cluster4_dst0_max.apply();
                }

                /* Stage 5 */
                if (meta.cluster1_dst1_distance == 0) {
                    tbl_compute_distance_cluster1_dst1_max.apply();
                }
                if (meta.cluster2_dst1_distance == 0) {
                    tbl_compute_distance_cluster2_dst1_max.apply();
                }
                if (meta.cluster3_dst1_distance == 0) {
                    tbl_compute_distance_cluster3_dst1_max.apply();
                }
                if (meta.cluster4_dst1_distance == 0) {
                    tbl_compute_distance_cluster4_dst1_max.apply();
                }

                /* Stage 6 */
                if (meta.cluster1_dst2_distance == 0) {
                    tbl_compute_distance_cluster1_dst2_max.apply();
                }            
                if (meta.cluster2_dst2_distance == 0) {
                    tbl_compute_distance_cluster2_dst2_max.apply();
                }
                if (meta.cluster3_dst2_distance == 0) {
                    tbl_compute_distance_cluster3_dst2_max.apply();
                }
                if (meta.cluster4_dst2_distance == 0) {
                    tbl_compute_distance_cluster4_dst2_max.apply();
                }
                //merge_dst1_to_dst0_1_2();
                //merge_dst1_to_dst0_3_4();
                merge_dst1_to_dst0();

                /* Stage 7 */
                if (meta.cluster1_dst3_distance == 0) {
                    tbl_compute_distance_cluster1_dst3_max.apply();
                }
                if (meta.cluster2_dst3_distance == 0) {
                    tbl_compute_distance_cluster2_dst3_max.apply();
                }
                if (meta.cluster3_dst3_distance == 0) {
                    tbl_compute_distance_cluster3_dst3_max.apply();
                }
                if (meta.cluster4_dst3_distance == 0) {
                    tbl_compute_distance_cluster4_dst3_max.apply();
                }
                merge_dst2_to_dst0();

                /* Stage 8 */
                merge_dst3_to_dst0();

                /* Stage 9 */
                compute_min_first();

                /* Stage 10 */
                compute_min_second();

                // We check if it is one of the first 4 packets, if it is, we initialize the cluster
                tbl_do_init_counter.apply();

                // We check if we need to update the clusters
                tbl_do_updateclusters_counter.apply();

                /* Stage 11 */
                if (meta.min_d1_d2_d3_d4 == meta.cluster1_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 1. Get prio from cluster 1 */
                    meta.rs.cluster_id = 1;
                } else if (meta.min_d1_d2_d3_d4 == meta.cluster2_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 2. Get prio from cluster 2 */
                    meta.rs.cluster_id = 2;
                } else if (meta.min_d1_d2_d3_d4 ==  meta.cluster3_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 3. Get prio from cluster 3 */
                    meta.rs.cluster_id = 3;
                } else if (meta.min_d1_d2_d3_d4 ==  meta.cluster4_dst0_distance && meta.init_counter_value == 0) {
                    /* We select cluster 4. Get prio from cluster 4 */
                    meta.rs.cluster_id = 4;
                } else {
                    meta.rs.cluster_id = meta.init_counter_value;
                    meta.rs.update_activated = 1;
                }
                ig_intr_md.resubmit_type = 1;

            } else {

                // Resubmitted packet
                if (meta.rs.update_activated == 1) {

                    // /* Stage 0 */
                    // tbl_do_update_cluster1_dst0_min.apply();
                    // tbl_do_update_cluster2_dst0_min.apply();
                    // tbl_do_update_cluster3_dst0_min.apply();
                    // tbl_do_update_cluster4_dst0_min.apply();

                    // /* Stage 1 */
                    // tbl_do_update_cluster1_dst1_min.apply();
                    // tbl_do_update_cluster2_dst1_min.apply();
                    // tbl_do_update_cluster3_dst1_min.apply();
                    // tbl_do_update_cluster4_dst1_min.apply();

                    /* Stage 2 */
                    // tbl_do_update_cluster1_dst2_min.apply();
                    // tbl_do_update_cluster2_dst2_min.apply();
                    // tbl_do_update_cluster3_dst2_min.apply();
                    // tbl_do_update_cluster4_dst2_min.apply();

                    // /* Stage 3 */
                    // tbl_do_update_cluster1_dst3_min.apply();
                    // tbl_do_update_cluster2_dst3_min.apply();
                    // tbl_do_update_cluster3_dst3_min.apply();
                    // tbl_do_update_cluster4_dst3_min.apply();

                    // /* Stage 4 */
                    // tbl_do_update_cluster1_dst0_max.apply();
                    // tbl_do_update_cluster2_dst0_max.apply();
                    // tbl_do_update_cluster3_dst0_max.apply();
                    // tbl_do_update_cluster4_dst0_max.apply();

                    // /* Stage 5 */
                    // tbl_do_update_cluster1_dst1_max.apply();
                    // tbl_do_update_cluster2_dst1_max.apply();
                    // tbl_do_update_cluster3_dst1_max.apply();
                    // tbl_do_update_cluster4_dst1_max.apply();

                    // /* Stage 6 */
                    // tbl_do_update_cluster1_dst2_max.apply();
                    // tbl_do_update_cluster2_dst2_max.apply();
                    // tbl_do_update_cluster3_dst2_max.apply();
                    // tbl_do_update_cluster4_dst2_max.apply();

                    // /* Stage 7 */
                    // tbl_do_update_cluster1_dst3_max.apply();
                    // tbl_do_update_cluster2_dst3_max.apply();
                    // tbl_do_update_cluster3_dst3_max.apply();
                    // tbl_do_update_cluster4_dst3_max.apply();
                    PortId_t port = ig_intr_md.egress_port;
                    if(meta.rs.cluster_id == 1) {
                        bit<32> data;
                        cluster1_dst0_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 < data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster1_dst0_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster1_dst0_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 > data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster1_dst0_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster1_dst1_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 < data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster1_dst1_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster1_dst1_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 > data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster1_dst1_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster1_dst2_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 < data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster1_dst2_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster1_dst2_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 > data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster1_dst2_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster1_dst3_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 < data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster1_dst3_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster1_dst3_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 > data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster1_dst3_max.write(ig_intr_md.egress_port, data);
                        }
                    } else if(meta.rs.cluster_id == 2) {
                        bit<32> data;
                        cluster2_dst0_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 < data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster2_dst0_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster2_dst0_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 > data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster2_dst0_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster2_dst1_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 < data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster2_dst1_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster2_dst1_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 > data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster2_dst1_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster2_dst2_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 < data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster2_dst2_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster2_dst2_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 > data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster2_dst2_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster2_dst3_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 < data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster2_dst3_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster2_dst3_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 > data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster2_dst3_max.write(ig_intr_md.egress_port, data);
                        }
                    } else if(meta.rs.cluster_id == 3) {
                        bit<32> data;
                        cluster3_dst0_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 < data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster3_dst0_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster3_dst0_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 > data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster3_dst0_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster3_dst1_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 < data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster3_dst1_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster3_dst1_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 > data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster3_dst1_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster3_dst2_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 < data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster3_dst2_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster3_dst2_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 > data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster3_dst2_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster3_dst3_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 < data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster3_dst3_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster3_dst3_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 > data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster3_dst3_max.write(ig_intr_md.egress_port, data);
                        }
                    } else if(meta.rs.cluster_id == 4) {
                        bit<32> data;
                        cluster4_dst0_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 < data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster4_dst0_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster4_dst0_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst0 > data) {
                            data = (bit<32>)hdr.ipv4.dst0;
                            cluster4_dst0_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster4_dst1_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 < data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster4_dst1_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster4_dst1_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst1 > data) {
                            data = (bit<32>)hdr.ipv4.dst1;
                            cluster4_dst1_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster4_dst2_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 < data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster4_dst2_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster4_dst2_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst2 > data) {
                            data = (bit<32>)hdr.ipv4.dst2;
                            cluster4_dst2_max.write(ig_intr_md.egress_port, data);
                        }
                        cluster4_dst3_min.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 < data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster4_dst3_min.write(ig_intr_md.egress_port, data);
                        }
                        cluster4_dst3_max.read(data, port);
                        if ((bit<32>)hdr.ipv4.dst3 > data) {
                            data = (bit<32>)hdr.ipv4.dst3;
                            cluster4_dst3_max.write(ig_intr_md.egress_port, data);
                        }

                    }
                }

                /* Stage 8: Get the priority and forward the resubmitted packet */
                cluster_to_prio.apply();

                /* Stage 9: Compute the amount of traffic mapped to each cluster */
                do_bytes_count.apply();

            }
        }

        
        if (ig_intr_md.resubmit_type == 1) {
            resubmit(meta.rs);
        }
        //pkt.emit(hdr); // If the header is valid, will emit it. If not valid, will just jump to the next one.
        
    }
}





/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

// Is the same as ipv4_h but with the destination address bytes altogether



struct my_egress_headers_t {
    ethernet_h ethernet;
    
}

struct my_egress_metadata_t {}

struct pair {
    bit<32>     first;
    bit<32>     second;
}

parser MyEgressParser(packet_in      pkt,
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    out standard_metadata_t eg_intr_md) {

        state start {
            //pkt.extract(eg_intr_md);
            transition parse_ethernet;
        }

        state parse_ethernet {
            pkt.extract(hdr.ethernet);
            transition select(hdr.ethernet.ether_type) {
                0x0800:  parse_ipv4_egress;
                default: accept;
            }
        }

        state parse_ipv4_egress {
            pkt.extract(hdr.ipv4_egress);
            transition accept;
        }
    }

control MyEgress(
    inout my_ingress_headers_t                          hdr,
    inout my_ingress_metadata_t                         meta,
    inout    standard_metadata_t                  eg_intr_md) {


    /* We measure throughput of benign and malicious traffic for evaluation */
    direct_counter(CounterType.bytes) bytes_counter_malicious_egress;
    direct_counter(CounterType.bytes) bytes_counter_benign_egress;

    action bytes_count_malicious_egress() {
         bytes_counter_malicious_egress.count();
    }

    action nop() {
    }

    action bytes_count_benign_egress() {
         bytes_counter_benign_egress.count();
    }

    table do_bytes_count_malicious_egress {
        key = {
            hdr.ipv4_egress.dst_addr : exact;
            //hdr.ipv4_egress.src_addr : exact; // carpet bombing        
        }
        actions = { 
            bytes_count_malicious_egress; 
            @defaultonly nop;
        }
        counters = bytes_counter_malicious_egress;
        const default_action = nop;
        size = 1024;
    }

    table do_bytes_count_benign_egress {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = { 
            bytes_count_benign_egress; 
        }
        counters = bytes_counter_benign_egress;
        const default_action = bytes_count_benign_egress;
        size = 1024;
    }

    
    register<bit<32>, bit<1>>(1) timestamp;
    action add_timestamp() {
        bit<32> data;
        timestamp.read(data, 0);
        data = eg_intr_md.egress_global_timestamp[47:16]; // 原始时间戳是 bit<48>
        timestamp.write(0, data);
    }

    action do_add_timestamp() {
        bit<32> data;
        timestamp.read(data, 0);
        data = eg_intr_md.egress_global_timestamp[47:16]; // 原始时间戳是 bit<48>
        timestamp.write(0, data);
    }

    table tbl_do_add_timestamp {
        actions = {
            do_add_timestamp;
        }
        const default_action = do_add_timestamp;
        size = 1;
    }

    apply {

        /* Stages 10 - 11 */      
        if (hdr.ipv4_egress.isValid()) {

            // We store the latest timestamp
            tbl_do_add_timestamp.apply();

            // If it is malicious:
            if (!do_bytes_count_malicious_egress.apply().hit){

                // If it is benign
                do_bytes_count_benign_egress.apply();
            
            }
        }
    }

}
control MyComputeChecksum(inout my_ingress_headers_t hdr,
                          inout my_ingress_metadata_t meta) {
    apply {
        // Add checksum computation logic here if needed
    }
}

control MyDeparser(packet_out pkt,
    in my_ingress_headers_t hdr) {

    apply {
        pkt.emit(hdr); // We do not emit eg_intr_md so that it does not go into the wire
    }
}

/*************************************************************************
 ****************  F I N A L  P A C K A G E    ***************************
 *************************************************************************/
 
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    

    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;