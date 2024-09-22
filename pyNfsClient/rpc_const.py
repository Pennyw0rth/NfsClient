# Types defined in RFC 1831
# RPC: Remote Procedure Call Protocol Specification Version 2

# Message types
CALL  = 0
REPLY = 1

# Reply status
MSG_ACCEPTED = 0
MSG_DENIED   = 1

# Accept status
SUCCESS       = 0
PROG_UNAVAIL  = 1
PROG_MISMATCH = 2
PROC_UNAVAIL  = 3
GARBAGE_ARGS  = 4
SYSTEM_ERR    = 5

# Reject status
RPC_MISMATCH = 0
AUTH_ERROR   = 1

# Auth flavors
AUTH_REASON = {
    0: "AUTH_OK",           # success
    # failed at the server
    1: "AUTH_BADCRED",      # bad credential
    2: "AUTH_REJECTEDCRED", # client must begin new session
    3: "AUTH_BADVERF",      # bad verifier
    4: "AUTH_REJECTEDVERF", # verifier expired or replayed
    5: "AUTH_TOOWEAK",      # rejected due to security reasons
    # failed locally
    6: "AUTH_INVALIDRESP",  # bogus response verifier
    7: "AUTH_FAILED",       # reason unknown
}

# Auth flavors
AUTH_NONE  = 0
AUTH_SYS   = 1
AUTH_SHORT = 2
