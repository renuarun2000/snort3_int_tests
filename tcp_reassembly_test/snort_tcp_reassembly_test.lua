-- Snort configuration to test TCP reassembly with partial flush, retransmits, and OOO packets

-- Network definitions
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
    show_rebuilt_packets = true,
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
    queue_limit = { max_bytes = 4194304, max_segments = 3000 },
    overlap_limit = 10,
    max_pdu = 16384,  -- Force PDU-based reassembly
    reassembly_policy = 'first',  -- Use first policy to highlight the issue
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
        trim_tcp_options = false,
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
    script_detection = true,
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

-- Enable packet capture for analysis
packet_capture = 
{
    enabled = true,
    limit = 100,
}

-- Enable file processing to trigger partial flush
file_id = 
{
    enable_type = true,
    enable_signature = true,
    enable_capture = true,
}

-- Enable detailed debug logs
debug = 
{
    file = 'debug.log',
    level = 255,  -- Maximum debug level
    loggers = 
    {
        'stream',
        'stream_tcp',
        'tcp_reassembler',
        'http_inspect',
        'file_api',
    }
}

-- Force packet trace
trace = 
{
    modules = 
    {
        { name = 'stream_tcp', level = 255 },
        { name = 'tcp_reassembler', level = 255 },
        { name = 'http_inspect', level = 255 },
    }
}

-- Enable profiling to see performance impact
profiler = 
{
    modules = true,
    memory = true,
    cpu = true,
}