-- Snort configuration to test PAWS timestamp validation

-- Home network definition
HOME_NET = '192.168.1.0/24'
EXTERNAL_NET = '10.1.1.0/24'

-- Include default configurations
dofile('snort_defaults.lua')

-- Stream configuration with detailed TCP tracking
stream = 
{
    tcp_cache = { max_sessions = 8192 },
    udp_cache = { max_sessions = 1024 },
    ip_cache = { max_sessions = 1024 },
}

stream_tcp = 
{
    policy = 'bsd',  -- Use BSD TCP stack behavior
    session_timeout = 180,
    max_window = 65535,
    track_only = false,
    log_asymmetric_traffic = true,
    show_rebuilt_packets = true,
    small_segments = 
    {
        count = 3,
        maximum_size = 20,
    },
    require_3whs = 0,
    paws_drop_zero_ts = true,  -- Drop packets with zero timestamp
}

-- Enable TCP normalization
normalizer = 
{
    tcp = 
    {
        ips = true,
        trim_syn = true,
        trim_rst = true,
        trim_win = true,
        trim_mss = true,
        trim_tcp_options = true,
        block = true,
    }
}

-- Configure logging
unified2 = 
{
    filename = 'unified2.log',
    limit = 128,
}

-- Alert output configuration
alert_csv = 
{
    file = true,
    fields = 'timestamp,msg,src,srcport,dst,dstport,proto,action',
}

-- Enable detailed TCP events
ips = 
{
    -- Rule to alert on bad TCP timestamps
    rules = [[
        alert tcp any any -> any any (msg:"TCP PAWS Timestamp Violation"; flow:established; detection_filter:track by_src, count 1, seconds 60; sid:1000001; rev:1;)
        alert tcp any any -> any any (msg:"TCP Bad Timestamp"; flow:established; sid:1000002; rev:1;)
    ]],
    enable_builtin_rules = true,
}

-- Configure output for debugging
output = 
{
    event_trace = { max_data = 4096 },
    wide_hex_dump = true,
}

-- Enable packet capture for analysis
packet_capture = 
{
    enabled = true,
    limit = 100,
}