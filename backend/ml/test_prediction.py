from ml.predict import predict_threat


result = predict_threat(
    duration=12,
    source_bytes=1500,
    destination_bytes=4200,
    source_port=52342,
    destination_port=443,
    failed_attempts=0,
    packet_count=52
)
print(result)