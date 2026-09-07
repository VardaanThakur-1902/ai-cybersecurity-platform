from ml.predict import predict_threat


normal_event = {
    "source_port": 12345,
    "destination_port": 80,
    "protocol": 1,
    "severity": 1,
    "event_type": 0,
    "is_ssh": 0,
    "is_http": 1,
    "is_suspicious_port": 0,
    "is_failed_login": 0,
    "is_port_scan": 0,
    "is_malware": 0,
    "suspicious_event_count": 0,
    "behavior_score": 0,
}


suspicious_event = {
    "source_port": 12345,
    "destination_port": 22,
    "protocol": 1,
    "severity": 4,
    "event_type": 2,
    "is_ssh": 1,
    "is_http": 0,
    "is_suspicious_port": 0,
    "is_failed_login": 1,
    "is_port_scan": 0,
    "is_malware": 0,
    "suspicious_event_count": 5,
    "behavior_score": 30,
}


print("\nNormal Event:")
print(predict_threat(normal_event))


print("\nSuspicious Event:")
print(predict_threat(suspicious_event))