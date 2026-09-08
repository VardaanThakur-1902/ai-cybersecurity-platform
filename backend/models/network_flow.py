from sqlmodel import Field, SQLModel


class NetworkFlow(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    source_ip: str
    destination_ip: str

    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None

    flow_duration: float = 0
    total_fwd_packets: float = 0
    total_backward_packets: float = 0

    total_length_fwd_packets: float = 0
    total_length_bwd_packets: float = 0

    fwd_packet_length_max: float = 0
    fwd_packet_length_min: float = 0

    bwd_packet_length_max: float = 0
    bwd_packet_length_min: float = 0

    flow_bytes_per_second: float = 0
    flow_packets_per_second: float = 0

    fwd_iat_total: float = 0
    bwd_iat_total: float = 0

    fwd_psh_flags: float = 0
    bwd_psh_flags: float = 0

    syn_flag_count: float = 0
    ack_flag_count: float = 0
    urg_flag_count: float = 0

    average_packet_size: float = 0

    active_mean: float = 0
    idle_mean: float = 0

    label: str | None = None

    ml_prediction: int | None = None
    attack_probability: float | None = None