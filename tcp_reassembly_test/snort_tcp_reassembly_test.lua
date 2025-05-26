-- Snort configuration to test TCP reassembly with partial flush, retransmits, and OOO packets

-- Network definitions
HOME_NET = '192.168.1.0/24'
EXTERNAL_NET = '10.1.1.0/24'

-- Include default configurations
dofile('snort_defaults.lua')

-- Stream configuration with detailed TCP tracking
stream = 
{
    -- Use idle_timeout instead of max_sessions for cache configurations
    tcp_cache = { idle_timeout = 180 },
    udp_cache = { idle_timeout = 180 },
    ip_cache = { idle_timeout = 180 },
    max_flows = 8192,  -- Overall maximum flows
}

stream_tcp = 
{
    policy = 'bsd',  -- Use BSD TCP stack behavior
    session_timeout = 180,
    max_window = 65535,
    track_only = false,
    show_rebuilt_packets = true,  -- This is valid in stream_tcp
    small_segments = 
    {
        count = 3,
        maximum_size = 20,
    },
    require_3whs = false,
    queue_limit = { max_bytes = 4194304, max_segments = 3000 },
    overlap_limit = 10,
    max_pdu = 16384,  -- Force PDU-based reassembly
}

-- Enable TCP normalization
normalizer = 
{
    tcp = 
    {
        ips = true,
        trim_syn = false,
        trim_rst = false,
        trim_win = false,
        trim_mss = false,
        opts = false,  -- Correct option name for TCP options normalization
        block = false,  -- Don't block to see all packets
    }
}

-- HTTP inspector to trigger partial flush
http_inspect = 
{
    request_depth = 65535,
    response_depth = 65535,
    unzip = true,
    normalize_utf = true,
    decompress_pdf = true,
    decompress_swf = true,
    decompress_zip = true,
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
    fields = "timestamp msg src srcport dst dstport proto action",
}

-- Enable detailed TCP events
ips = 
{
    -- Rules to detect specific TCP conditions
    rules = [[
        alert tcp any any -> any any (msg:"TCP Retransmission"; flow:established; detection_filter:track by_src, count 1, seconds 60; sid:1000001; rev:1;)
        alert tcp any any -> any any (msg:"TCP Out of Order Packet"; flow:established; detection_filter:track by_src, count 1, seconds 60; sid:1000002; rev:1;)
        alert tcp any any -> any any (msg:"HTTP Request"; flow:established,to_server; content:"GET"; http_method; sid:1000003; rev:1;)
        alert tcp any any -> any any (msg:"HTTP Response"; flow:established,to_client; content:"HTTP/1.1 200 OK"; sid:1000004; rev:1;)
    ]],
    enable_builtin_rules = true,
}

-- Configure output for debugging
output = 
{
    event_trace = { max_data = 4096 },
    wide_hex_dump = true,
}

-- File processing configuration
file_id = 
{
    type_depth = 1460,
    signature_depth = 10485760,
    trace_type = true,
    trace_signature = true,
    trace_stream = true,
}

-- File policy configuration
file_policy = 
{
    enable_type = true,
    enable_signature = true,
    enable_capture = true,
    rules =
    {
        {  when = { file_type_id = 288 }, use = { verdict = 'log' } },
    }
}

-- Enable detailed debug logs
logger = 
{
    level = 'debug',
}

-- Configure packet trace
packet_tracer = 
{
    enable = true,
}

-- Configure trace for specific modules
-- Fixed module names to match actual Snort 3 module names
trace = 
{
    modules = 
    {
        stream_tcp = { level = 255 },
        stream_ip = { level = 255 },
        tcp_reassembly = { level = 255 },
        http_inspect = { level = 255 },
    }
}

-- Configure profiler
profiler = 
{
    rules = { show = true },
    cpu = { show = true },
    memory = { show = true },
}


