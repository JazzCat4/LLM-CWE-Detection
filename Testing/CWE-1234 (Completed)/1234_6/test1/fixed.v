module test_secure (
    input         clk,
    input         rst_n,
    input         wr_req,
    input  [15:0] din,
    input         lock_flag,      // hardware-derived lifecycle/lock fuse
    input         scan_mode,      // debug indication (cannot override lock)
    input         priv_wr,        // hardware privilege check for writes
    input         glitch_detect,  // from glitch detector
    output reg [15:0] dout
);
    // One-way lock fuse
    reg lock_status;
    // Simple FSM: 0 = UNLOCKED, 1 = LOCKED, 2 = ERROR
    reg [1:0] sec_state;

    localparam ST_UNLOCKED = 2'b00;
    localparam ST_LOCKED   = 2'b01;
    localparam ST_ERROR    = 2'b10;

    // Lock / state control
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            lock_status <= 1'b0;
            sec_state   <= ST_UNLOCKED;
        end else if (glitch_detect) begin
            // CWE-1247: force safe error state on glitch
            lock_status <= 1'b1;      // permanently lock
            sec_state   <= ST_ERROR;  // defensive default
        end else begin
            // One-way lock fuse (CWE-1234, CWE-1262, CWE-1256)
            if (lock_flag && !lock_status) begin
                lock_status <= 1'b1;
                sec_state   <= ST_LOCKED;
            end
        end
    end

    // Data register with strict access control and scrubbing
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // CWE-226: scrub on reset
            dout <= 16'h0000;
        end else if (glitch_detect) begin
            // CWE-1247: safe value on glitch
            dout <= 16'h0000;
        end else begin
            // CWE-226: scrub on lock transition or entering debug
            if (lock_flag && !lock_status)
                dout <= 16'h0000;
            else if (scan_mode && sec_state == ST_UNLOCKED)
                // entering debug from unlocked: clear before reuse
                dout <= 16'h0000;
            else begin
                // CWE-1262 / CWE-1256:
                // - default deny when locked
                // - require hardware privilege
                // - debug/scan cannot override lock
                if (wr_req && priv_wr && !lock_status && sec_state == ST_UNLOCKED)
                    dout <= din;
                else
                    dout <= dout; // hold
            end
        end
    end

endmodule
