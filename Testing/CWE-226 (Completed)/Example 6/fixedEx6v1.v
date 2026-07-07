module secret_fifo_secure (
    input  wire        clk,
    input  wire        rst,

    // Original data/control interface
    input  wire        push,
    input  wire        pop,
    input  wire [63:0] key_in,
    output reg  [63:0] key_out,
    output reg         empty,
    output reg         full,

    // Security / privilege / debug / glitch
    input  wire        priv_access,    // 1 = privileged, 0 = unprivileged
    input  wire        lock_set,       // one-time lock fuse (set-only)
    input  wire        debug_mode,     // debug/test indicator (must NOT bypass lock)
    input  wire        glitch_detect,  // from external glitch detector

    // Status
    output reg         locked,
    output reg         error_flag
);

    reg [63:0] key [0:3];
    reg [1:0]  head, tail;
    reg [2:0]  count;
    reg [2:0]  count_shadow;   // simple redundant encoding for glitch/error detection

    integer i;

    // Synchronous logic
    always @(posedge clk) begin
        // Defensive default: any glitch forces error state (CWE-1247)
        if (glitch_detect) begin
            error_flag <= 1'b1;
            // Zeroize all secrets on error (CWE-226)
            for (i = 0; i < 4; i = i + 1)
                key[i] <= 64'h0;
            key_out      <= 64'h0;
            head         <= 0;
            tail         <= 0;
            count        <= 0;
            count_shadow <= 0;
        end else if (rst) begin
            // Reset: zeroize all storage (CWE-226)
            head         <= 0;
            tail         <= 0;
            count        <= 0;
            count_shadow <= 0;
            key_out      <= 64'h0;
            error_flag   <= 1'b0;
            // lock is NOT cleared by reset (one-time fuse, CWE-1234)
            for (i = 0; i < 4; i = i + 1)
                key[i] <= 64'h0;
        end else begin
            // One-time programmable lock (CWE-1234/1262)
            if (lock_set)
                locked <= 1'b1;

            // Glitch detection via redundant count (CWE-1247)
            if (count != count_shadow) begin
                error_flag <= 1'b1;
                for (i = 0; i < 4; i = i + 1)
                    key[i] <= 64'h0;
                key_out      <= 64'h0;
                head         <= 0;
                tail         <= 0;
                count        <= 0;
                count_shadow <= 0;
            end else if (!error_flag) begin
                // Debug mode must NOT bypass lock or privilege (CWE-1234)
                if (!debug_mode) begin
                    // Privilege-gated, default-deny (CWE-1256/1262)
                    if (push && priv_access && !locked && !full) begin
                        key[tail] <= key_in;
                        tail      <= tail + 1'b1;
                        count        <= count + 1'b1;
                        count_shadow <= count_shadow + 1'b1;
                    end

                    if (pop && priv_access && !locked && !empty) begin
                        key_out   <= key[head];
                        // Overwrite key immediately after use (CWE-226)
                        key[head] <= 64'h0;
                        head      <= head + 1'b1;
                        count        <= count - 1'b1;
                        count_shadow <= count_shadow - 1'b1;
                    end
                end
            end
        end
    end

    // Combinational flags (correct depth = 4, fix off-by-one)
    always @(*) begin
        empty = (count == 0);
        full  = (count == 4);
    end

endmodule
