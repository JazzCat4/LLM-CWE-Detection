module secure_test (
    input  wire        clk,
    input  wire        rst,

    // Original-style interface
    input  wire        write_req,
    input  wire        read_req,
    input  wire [1:0]  addr,
    input  wire [127:0] secret_key_in,
    output reg  [127:0] secret_key_out,

    // Security / privilege controls
    input  wire [1:0]  priv_level,    // 2'b11 = highest privilege
    input  wire        secure_domain, // 1 = secure world, 0 = non-secure
    input  wire        lock_keys,     // write-once lock for key reads
    input  wire        zeroize        // explicit scrub command
);

    // Internal key storage (sensitive)
    reg [127:0] secret_key [0:3];

    // Simple constant mask to reduce direct correlation (basic side-channel hardening)
    localparam [127:0] MASK = 128'hA5A5_A5A5_A5A5_A5A5_A5A5_A5A5_A5A5_A5A5;

    // Privilege / access control
    wire privileged    = (priv_level == 2'b11) && secure_domain;
    wire write_en_int  = privileged && write_req;
    wire read_en_int   = privileged && read_req && !lock_keys;

    integer i;

    always @(posedge clk) begin
        if (rst) begin
            // CWE-226: scrub all sensitive storage on reset
            for (i = 0; i < 4; i = i + 1) begin
                secret_key[i] <= 128'b0;
            end
            secret_key_out <= 128'b0;
        end else begin
            // CWE-226 / CWE-1189: explicit zeroize for domain/context switch
            if (zeroize) begin
                for (i = 0; i < 4; i = i + 1) begin
                    secret_key[i] <= 128'b0;
                end
                secret_key_out <= 128'b0;
            end else begin
                // CWE-1256 / CWE-1262: privilege-gated write path
                if (write_en_int) begin
                    secret_key[addr] <= secret_key_in;
                end

                // CWE-1262: privilege-gated read path, default-deny
                if (read_en_int) begin
                    // If key is non-zero, return masked value; if scrubbed (zero), return 0
                    if (secret_key[addr] != 128'b0)
                        secret_key_out <= secret_key[addr] ^ MASK;  // masked key
                    else
                        secret_key_out <= 128'b0;                   // scrubbed / empty
                end else begin
                    // Default-deny for sensitive output
                    secret_key_out <= 128'b0;
                end
            end
        end
    end

endmodule
