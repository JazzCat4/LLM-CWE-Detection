module test_secure (
    input  wire        clk,
    input  wire        rst_n,

    // Secret inputs
    input  wire        secret_bit,
    input  wire [7:0]  secret_data,

    // Security / privilege controls
    input  wire        privileged,     // 1 = trusted/privileged domain
    input  wire        secure_mode,    // 1 = in sensitive/crypto context
    input  wire        lock_fuse,      // 1 = lock set, reset must NOT override secrets
    input  wire        glitch_detect,  // 1 = fault detected

    // Outputs
    output reg  [7:0]  acc_internal,   // internal secret state (not for unprivileged use)
    output wire [7:0]  acc_public,     // masked/public view
    output reg         error           // error state on glitch
);

    // Public view: default-deny, only privileged + secure_mode can see secret
    assign acc_public = (privileged && secure_mode && !error) ? acc_internal : 8'd0;

    // Track previous secure_mode to scrub on exit
    reg secure_mode_d;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // CWE-226: scrub on reset when not locked
            // CWE-1234: lock_fuse prevents reset from overriding locked secrets
            if (!lock_fuse) begin
                acc_internal <= 8'd0;
            end
            error          <= 1'b0;
            secure_mode_d  <= 1'b0;
        end else begin
            secure_mode_d <= secure_mode;

            // CWE-1247: glitch forces safe error state and freezes secret state
            if (glitch_detect) begin
                error <= 1'b1;
                // Optionally scrub on glitch as well
                acc_internal <= 8'd0;
            end else begin
                // CWE-226: scrub when leaving secure context
                if (secure_mode_d && !secure_mode) begin
                    acc_internal <= 8'd0;
                end else if (secure_mode && privileged && !error) begin
                    // Normal secret-dependent operation only in secure, privileged context
                    if (secret_bit) begin
                        acc_internal <= acc_internal + secret_data;
                    end
                    // else: hold value
                end
                // else: non-secure / unprivileged context, no secret updates
                error <= 1'b0;
            end
        end
    end

endmodule
