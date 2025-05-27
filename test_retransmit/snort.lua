-- Basic network settings
HOME_NET = "10.1.0.0/16"
EXTERNAL_NET = "any"

-- Include default configurations
dofile('snort_defaults.lua')

-- Stream configuration
stream = { }
stream_tcp = { 
    show_rebuilt_packets = true,
    session_timeout = 180,
    flush_factor = 0
}

-- HTTP Inspector
http_inspect = { }

-- File magic configuration
file_magic = {
    {
        id = 1,
        type = 'TEST_FILE',
        msg = 'Test File',
        rev = 1,
        magic = { { content = '|4D 41 4C 57 41 52 45|', offset = 0 } } -- "MALWARE" in hex
    }
}

-- File policy configuration
file_policy = {
    enable_type = true,
    enable_signature = true,
    enable_capture = true,
    verdict_delay = 5000, -- 5 second delay to simulate slow file lookup
    rules = {
        {
            when = { file_type_id = 1 }, -- TEST_FILE type
            use = { 
                verdict = "log",         -- Use "log" verdict instead of "block"
                enable_file_signature = true
            }
        }
    }
}

-- File ID configuration
file_id = {
    rules_file = 'file_magic.rules'  -- Use the built-in file magic rules
}

-- Wizard for protocol identification
wizard = default_wizard

-- IPS rules
local_rules = [[
alert tcp any any -> any any (
    msg:"Test File Detected"; 
    file_data; 
    content:"MALWARE"; 
    sid:1000001; 
    rev:1;
)
]]

ips = {
    enable_builtin_rules = true,
    rules = local_rules,
}

-- Packet processing configuration
packet_tracer = {
    enable = true,
    output = 'stdout',
    proto = 'all'
}

-- Logging configuration
alert_fast = {
    file = true,
    packet = true
}

file_log = {
    log_pkt_time = true,
    log_sys_time = true
}

-- Enable packet retry
active = {
    retry_queue_limit = 1024,
    max_responses = 10
}

-- Trace options for debugging
trace = {
    modules = {
        file_api = { all = 3 },
        stream_tcp = { all = 2 },
        active = { all = 2 },
        packet_io = { all = 2 }
    }
}
