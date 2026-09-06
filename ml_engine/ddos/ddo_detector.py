import os
import math
import pickle
import joblib

from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# MODEL CONFIGURATION
# ============================================================

PRODUCTION_THRESHOLD = 0.1


FEATURE_NAMES = [
    "packets_per_second",
    "bytes_per_second",
    "byte_asymmetry",
    "packet_asymmetry",
    "bidirectional_ratio",
    "syn_ratio",
    "rst_ratio",
    "syn_without_data",
    "unique_source_ips_5s",
    "source_ip_entropy_5s",
    "flows_30s",
    "unique_sources_30s",
    "protocol_diversity_30s",
    "byte_rate_mean_30s",
    "flows_60s",
    "unique_sources_60s",
    "protocol_diversity_60s",
    "byte_rate_mean_60s",
    "protocolName_igmp",
    "protocolName_ip",
    "protocolName_ipv6icmp",
    "protocolName_tcp_ip",
    "protocolName_udp_ip",
    "direction_L2R",
    "direction_R2L",
    "direction_R2R",
]


CONTINUOUS_COLS = [
    "packets_per_second",
    "bytes_per_second",
    "unique_source_ips_5s",
    "source_ip_entropy_5s",
    "byte_asymmetry",
    "packet_asymmetry",
    "bidirectional_ratio",
    "flows_30s",
    "unique_sources_30s",
    "protocol_diversity_30s",
    "byte_rate_mean_30s",
    "flows_60s",
    "unique_sources_60s",
    "protocol_diversity_60s",
    "byte_rate_mean_60s",
]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def calculate_entropy(values):
    """
    Calculate Shannon entropy.

    Used for:
        source_ip_entropy_5s
    """

    if not values:
        return 0.0

    counts = {}

    for value in values:
        counts[value] = counts.get(value, 0) + 1

    total = len(values)

    entropy = 0.0

    for count in counts.values():

        probability = count / total

        entropy -= probability * math.log2(probability)

    return entropy


def get_severity(probability):
    """
    Application-level severity mapping.
    """

    if probability >= 0.90:
        return "CRITICAL"

    if probability >= 0.70:
        return "HIGH"

    if probability >= 0.40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# DDoS FEATURE WINDOW
# ============================================================

class DDoSFeatureWindow:

    """
    Stateful feature aggregation.

    Aggregation is grouped by:

        destination + fixed 5-second bucket
        destination + fixed 30-second bucket
        destination + fixed 60-second bucket

    Events should preferably arrive in chronological order.
    """

    def __init__(self):

        # destination -> bucket -> events

        self.events_5s = defaultdict(
            lambda: defaultdict(list)
        )

        self.events_30s = defaultdict(
            lambda: defaultdict(list)
        )

        self.events_60s = defaultdict(
            lambda: defaultdict(list)
        )


    # ========================================================
    # CLEANUP
    # ========================================================

    def cleanup(self, destination, current_time):

        """
        Remove old buckets.

        This prevents unlimited memory growth.
        """

        cutoff_5s = (
            current_time.floor("5s")
            - pd.Timedelta(minutes=2)
        )

        cutoff_30s = (
            current_time.floor("30s")
            - pd.Timedelta(minutes=5)
        )

        cutoff_60s = (
            current_time.floor("60s")
            - pd.Timedelta(minutes=10)
        )


        self.events_5s[destination] = {

            bucket: events

            for bucket, events
            in self.events_5s[destination].items()

            if bucket >= cutoff_5s

        }


        self.events_30s[destination] = {

            bucket: events

            for bucket, events
            in self.events_30s[destination].items()

            if bucket >= cutoff_30s

        }


        self.events_60s[destination] = {

            bucket: events

            for bucket, events
            in self.events_60s[destination].items()

            if bucket >= cutoff_60s

        }


    # ========================================================
    # BUILD FEATURES
    # ========================================================

    def build_features(self, event):

        """
        Convert a raw network flow event into the
        exact 26 features expected by the model.
        """


        # ====================================================
        # TIMESTAMP
        # ====================================================

        start = pd.to_datetime(
            event["startDateTime"]
        )

        stop = pd.to_datetime(
            event["stopDateTime"]
        )


        # ====================================================
        # NETWORK IDENTIFIERS
        # ====================================================

        source = (
            event.get("source")
            or event.get("src_ip")
            or "unknown"
        )


        destination = (
            event.get("destination")
            or event.get("dst_ip")
            or "unknown"
        )


        protocol = str(

            event.get("protocolName")

            or event.get("protocol")

            or ""

        ).lower()


        direction = str(

            event.get("direction")

            or ""

        )


        # ====================================================
        # FLOW VALUES
        # ====================================================

        source_bytes = float(

            event.get(

                "totalSourceBytes",

                event.get("orig_bytes", 0)

            )

            or 0

        )


        destination_bytes = float(

            event.get(

                "totalDestinationBytes",

                event.get("resp_bytes", 0)

            )

            or 0

        )


        source_packets = float(

            event.get(

                "totalSourcePackets",

                event.get("orig_pkts", 0)

            )

            or 0

        )


        destination_packets = float(

            event.get(

                "totalDestinationPackets",

                event.get("resp_pkts", 0)

            )

            or 0

        )


        # ====================================================
        # DURATION
        # ====================================================

        duration = max(

            (stop - start).total_seconds(),

            0.001

        )


        total_bytes = (

            source_bytes

            + destination_bytes

        )


        total_packets = (

            source_packets

            + destination_packets

        )


        # ====================================================
        # TCP FLAGS
        # ====================================================

        tcp_flags = str(

            event.get(

                "sourceTCPFlagsDescription",

                ""

            )

            or ""

        )


        syn_ratio = int(

            "S" in tcp_flags

            or "s" in tcp_flags

        )


        rst_ratio = int(

            "R" in tcp_flags

            or "r" in tcp_flags

        )


        syn_without_data = int(

            syn_ratio == 1

            and source_bytes < 100

        )


        # ====================================================
        # PER-FLOW FEATURES
        # ====================================================

        packets_per_second = (

            total_packets

            / duration

        )


        bytes_per_second = (

            total_bytes

            / duration

        )


        byte_asymmetry = (

            abs(

                source_bytes

                - destination_bytes

            )

            / (total_bytes + 1)

        )


        packet_asymmetry = (

            abs(

                source_packets

                - destination_packets

            )

            / (total_packets + 1)

        )


        bidirectional_ratio = (

            destination_bytes

            / (total_bytes + 1)

        )


        # ====================================================
        # INTERNAL EVENT REPRESENTATION
        # ====================================================

        internal_event = {

            "timestamp": start,

            "source": source,

            "destination": destination,

            "protocolName": protocol,

            "bytes_per_second": bytes_per_second,

        }


        # ====================================================
        # FIXED TIME BUCKETS
        # ====================================================

        bucket_5s = start.floor("5s")

        bucket_30s = start.floor("30s")

        bucket_60s = start.floor("60s")


        # ====================================================
        # STORE EVENT
        # ====================================================

        self.events_5s[destination][
            bucket_5s
        ].append(
            internal_event
        )


        self.events_30s[destination][
            bucket_30s
        ].append(
            internal_event
        )


        self.events_60s[destination][
            bucket_60s
        ].append(
            internal_event
        )


        # ====================================================
        # GET EVENTS IN CURRENT FIXED BUCKETS
        # ====================================================

        events_5 = (

            self.events_5s[destination][
                bucket_5s
            ]

        )


        events_30 = (

            self.events_30s[destination][
                bucket_30s
            ]

        )


        events_60 = (

            self.events_60s[destination][
                bucket_60s
            ]

        )


        # ====================================================
        # 5 SECOND FEATURES
        # ====================================================

        unique_source_ips_5s = len(

            {

                item["source"]

                for item in events_5

            }

        )


        source_ip_entropy_5s = calculate_entropy(

            [

                item["source"]

                for item in events_5

            ]

        )


        # ====================================================
        # 30 SECOND FEATURES
        # ====================================================

        flows_30s = len(
            events_30
        )


        unique_sources_30s = len(

            {

                item["source"]

                for item in events_30

            }

        )


        protocol_diversity_30s = len(

            {

                item["protocolName"]

                for item in events_30

            }

        )


        if events_30:

            byte_rate_mean_30s = (

                sum(

                    item["bytes_per_second"]

                    for item in events_30

                )

                / len(events_30)

            )

        else:

            byte_rate_mean_30s = 0.0


        # ====================================================
        # 60 SECOND FEATURES
        # ====================================================

        flows_60s = len(
            events_60
        )


        unique_sources_60s = len(

            {

                item["source"]

                for item in events_60

            }

        )


        protocol_diversity_60s = len(

            {

                item["protocolName"]

                for item in events_60

            }

        )


        if events_60:

            byte_rate_mean_60s = (

                sum(

                    item["bytes_per_second"]

                    for item in events_60

                )

                / len(events_60)

            )

        else:

            byte_rate_mean_60s = 0.0


        # ====================================================
        # BUILD FINAL FEATURE DICTIONARY
        # ====================================================

        features = {


            # ------------------------------------------------
            # PER FLOW FEATURES
            # ------------------------------------------------

            "packets_per_second":
                packets_per_second,


            "bytes_per_second":
                bytes_per_second,


            "byte_asymmetry":
                byte_asymmetry,


            "packet_asymmetry":
                packet_asymmetry,


            "bidirectional_ratio":
                bidirectional_ratio,


            "syn_ratio":
                syn_ratio,


            "rst_ratio":
                rst_ratio,


            "syn_without_data":
                syn_without_data,


            # ------------------------------------------------
            # 5 SECOND FEATURES
            # ------------------------------------------------

            "unique_source_ips_5s":
                unique_source_ips_5s,


            "source_ip_entropy_5s":
                source_ip_entropy_5s,


            # ------------------------------------------------
            # 30 SECOND FEATURES
            # ------------------------------------------------

            "flows_30s":
                flows_30s,


            "unique_sources_30s":
                unique_sources_30s,


            "protocol_diversity_30s":
                protocol_diversity_30s,


            "byte_rate_mean_30s":
                byte_rate_mean_30s,


            # ------------------------------------------------
            # 60 SECOND FEATURES
            # ------------------------------------------------

            "flows_60s":
                flows_60s,


            "unique_sources_60s":
                unique_sources_60s,


            "protocol_diversity_60s":
                protocol_diversity_60s,


            "byte_rate_mean_60s":
                byte_rate_mean_60s,

        }


        # ====================================================
        # PROTOCOL FEATURES
        # ====================================================

        features["protocolName_igmp"] = int(
            protocol == "igmp"
        )


        features["protocolName_ip"] = int(
            protocol == "ip"
        )


        features["protocolName_ipv6icmp"] = int(
            protocol == "ipv6icmp"
        )


        features["protocolName_tcp_ip"] = int(
            protocol == "tcp_ip"
        )


        features["protocolName_udp_ip"] = int(
            protocol == "udp_ip"
        )


        # ====================================================
        # DIRECTION FEATURES
        # ====================================================

        features["direction_L2R"] = int(
            direction == "L2R"
        )


        features["direction_R2L"] = int(
            direction == "R2L"
        )


        features["direction_R2R"] = int(
            direction == "R2R"
        )


        # ====================================================
        # CLEAN OLD STATE
        # ====================================================

        self.cleanup(

            destination,

            start

        )


        # ====================================================
        # RETURN FEATURES
        # ====================================================

        return features


# ============================================================
# DDoS DETECTOR
# ============================================================

class DDoSDetector:


    def __init__(

        self,

        model_path=None,

        scaler_path=None,

        threshold=PRODUCTION_THRESHOLD

    ):


        # ----------------------------------------------------
        # DEFAULT MODEL DIRECTORY
        # ----------------------------------------------------

        base_dir = Path(
            __file__
        ).resolve().parent


        if model_path is None:

            model_path = base_dir / (
                "xgboost_ddos_model.pkl"
            )


        if scaler_path is None:

            scaler_path = base_dir / (
                "robust_scaler.pkl"
            )


        self.model_path = Path(
            model_path
        )


        self.scaler_path = Path(
            scaler_path
        )


        self.threshold = threshold


        # ----------------------------------------------------
        # LOAD MODEL
        # ----------------------------------------------------

        self.model = joblib.load(
            self.model_path
        )


        # ----------------------------------------------------
        # LOAD SCALER
        # ----------------------------------------------------

        self.scaler = joblib.load(
            self.scaler_path
        )


        # ----------------------------------------------------
        # CREATE FEATURE WINDOW
        # ----------------------------------------------------

        self.feature_window = (
            DDoSFeatureWindow()
        )


    # ========================================================
    # PREPARE MODEL INPUT
    # ========================================================

    def prepare_input(self, features):


        # ----------------------------------------------------
        # EXACT FEATURE ORDER
        # ----------------------------------------------------

        X = pd.DataFrame(

            [[

                features.get(
                    feature,
                    0.0
                )

                for feature
                in FEATURE_NAMES

            ]],

            columns=FEATURE_NAMES

        )


        # ----------------------------------------------------
        # HANDLE INVALID VALUES
        # ----------------------------------------------------

        X = X.replace(

            [

                np.inf,

                -np.inf

            ],

            np.nan

        )


        X = X.fillna(
            0.0
        )


        # ----------------------------------------------------
        # SCALE ONLY 15 CONTINUOUS FEATURES
        # ----------------------------------------------------

        X[CONTINUOUS_COLS] = (

            self.scaler.transform(

                X[CONTINUOUS_COLS]

            )

        )


        return X


    # ========================================================
    # PREDICT
    # ========================================================

    def predict(self, event):


        # ----------------------------------------------------
        # BUILD 26 FEATURES
        # ----------------------------------------------------

        features = (

            self.feature_window.build_features(
                event
            )

        )


        # ----------------------------------------------------
        # PREPARE INPUT
        # ----------------------------------------------------

        X = self.prepare_input(
            features
        )


        # ----------------------------------------------------
        # MODEL PROBABILITY
        # ----------------------------------------------------

        probability = float(

            self.model.predict_proba(
                X
            )[0][1]

        )


        # ----------------------------------------------------
        # THRESHOLD CHECK
        # ----------------------------------------------------

        detected = (

            probability >= self.threshold

        )


        # ----------------------------------------------------
        # NO ALERT
        # ----------------------------------------------------

        if not detected:

            return None


        # ----------------------------------------------------
        # SEVERITY
        # ----------------------------------------------------

        severity = get_severity(
            probability
        )


        # ----------------------------------------------------
        # EVIDENCE
        # ----------------------------------------------------

        evidence = {

            "destination":

                event.get(
                    "destination",
                    event.get(
                        "dst_ip"
                    )
                ),


            "source":

                event.get(
                    "source",
                    event.get(
                        "src_ip"
                    )
                ),


            "packets_per_second":

                features[
                    "packets_per_second"
                ],


            "bytes_per_second":

                features[
                    "bytes_per_second"
                ],


            "unique_source_ips_5s":

                features[
                    "unique_source_ips_5s"
                ],


            "source_ip_entropy_5s":

                features[
                    "source_ip_entropy_5s"
                ],


            "flows_30s":

                features[
                    "flows_30s"
                ],


            "unique_sources_30s":

                features[
                    "unique_sources_30s"
                ],


            "flows_60s":

                features[
                    "flows_60s"
                ],


            "unique_sources_60s":

                features[
                    "unique_sources_60s"
                ],


            "syn_ratio":

                features[
                    "syn_ratio"
                ],


            "syn_without_data":

                features[
                    "syn_without_data"
                ],

        }


        # ----------------------------------------------------
        # RETURN DETECTION RESULT
        # ----------------------------------------------------

        return {

            "detector":

                "DDoSDetector",


            "detected":

                True,


            "label":

                "DDoS",


            "confidence":

                probability,


            "severity":

                severity,


            "threshold":

                self.threshold,


            "evidence":

                evidence,

        }


# ============================================================
# OPTIONAL TEST
# ============================================================

if __name__ == "__main__":

    print(
        "DDoSDetector module loaded successfully."
    )