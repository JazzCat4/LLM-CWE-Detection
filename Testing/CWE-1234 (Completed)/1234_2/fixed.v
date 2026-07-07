module test_secure (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        debug_mode,      // debug mode, now constrained
    input  wire        lock_config,     // request to lock configuration (privileged-only)
    input  wire        write_enable,
    input  wire        secure_access,   // NEW: indicates privileged/trusted master
    input  wire        glitch_detect,   // NEW: glitch detector input
    input  wire [7:0]  addr,
    input  wire [31:0] data_in,
    output reg  [31:0] data_out
);

    reg [31:0] config_regs [0:255];
    reg        config_locked;
    reg [31:0] mpu_config;

    integer i;

    // Sequential logic with full scrubbing and hardened access control
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // CWE-226: scrub sensitive state on reset
            config_locked <= 1'b0;
            mpu_config    <= 32'h0000_0000;
            for (i = 0; i < 256; i = i + 1) begin
                config_regs[i] <= 32'h0000_0000;
            end
        end else begin
            // CWE-1247: glitch forces safe state, deny all writes
            if (glitch_detect) begin
                config_locked <= 1'b1;      // force locked
                mpu_config    <= 32'h0000_0000;
            end else begin
                // CWE-1234/1191: debug cannot override lock; debug is read-only
                // CWE-1262/1256/1189: only secure_access can write sensitive regs
                if (write_enable && secure_access && !debug_mode && !config_locked) begin
                    if (addr < 8'hFF) begin
                        case (addr)
                            8'h10: mpu_config <= data_in;          // MPU config (privileged)
                            default: config_regs[addr] <= data_in; // general config
                        endcase
                    end
                end

                // CWE-1234/1262: lock bit is one-way, privileged-only, not data-driven
                if (secure_access && lock_config && !config_locked) begin
                    config_locked <= 1'b1; // one-time programmable lock
                end
            end

            // CWE-1191: entering debug mode clears sensitive state
            if (debug_mode) begin
                mpu_config <= 32'h0000_0000;
            end
        end
    end

    // Combinational read path with access control
    always @(*) begin
        // CWE-1262: default-deny for sensitive registers to unprivileged
        if (glitch_detect) begin
            data_out = 32'h0000_0000; // safe default on glitch
        end else if (addr == 8'h10) begin
            // MPU config: privileged-only visibility
            data_out = secure_access ? mpu_config : 32'h0000_0000;
        end else if (addr == 8'hFF) begin
            // Lock status: mask to unprivileged
            data_out = secure_access ? {31'b0, config_locked} : 32'h0000_0000;
        end else begin
            // General config: readable, but scrubbed on reset
            data_out = config_regs[addr];
        end
    end

endmodule
