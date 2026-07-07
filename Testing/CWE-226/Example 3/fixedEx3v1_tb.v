`timescale 1ns/1ps

module tb_secure_test;

    reg clk;
    reg rst;
    reg write_req;
    reg read_req;
    reg [1:0] addr;
    reg [127:0] secret_key_in;
    wire [127:0] secret_key_out;

    reg [1:0] priv_level;
    reg       secure_domain;
    reg       lock_keys;
    reg       zeroize;

    // DUT
    secure_test dut (
        .clk(clk),
        .rst(rst),
        .write_req(write_req),
        .read_req(read_req),
        .addr(addr),
        .secret_key_in(secret_key_in),
        .secret_key_out(secret_key_out),
        .priv_level(priv_level),
        .secure_domain(secure_domain),
        .lock_keys(lock_keys),
        .zeroize(zeroize)
    );

    // Clock
    always #5 clk = ~clk;

    initial begin
        clk = 0;
        rst = 0;
        write_req = 0;
        read_req = 0;
        addr = 0;
        secret_key_in = 0;
        priv_level = 2'b00;
        secure_domain = 1'b0;
        lock_keys = 1'b0;
        zeroize = 1'b0;

        $display("\n=== Secure Module CWE Validation Testbench ===\n");

        // ------------------------------------------------------------
        // CWE-226: Scrubbing on reset and zeroize
        // ------------------------------------------------------------
        $display("CWE-226: Verify keys are scrubbed on reset and zeroize");

        // Privileged, secure write
        priv_level = 2'b11;
        secure_domain = 1'b1;
        addr = 2'b01;
        secret_key_in = 128'hDEADBEEF_DEADBEEF_DEADBEEF_DEADBEEF;
        write_req = 1; #10 write_req = 0;

        // Reset should scrub keys
        rst = 1; #10 rst = 0;

        read_req = 1; #10 read_req = 0;
        $display("After reset, secret_key_out = %h (should be 0)", secret_key_out);

        // Write again, then zeroize
        addr = 2'b01;
        secret_key_in = 128'hCAFEBABE_CAFEBABE_CAFEBABE_CAFEBABE;
        write_req = 1; #10 write_req = 0;

        zeroize = 1; #10 zeroize = 0;

        read_req = 1; #10 read_req = 0;
        $display("After zeroize, secret_key_out = %h (should be 0)", secret_key_out);

        // ------------------------------------------------------------
        // CWE-1189 / CWE-1256 / CWE-1262:
        // Unprivileged / non-secure access must be blocked
        // ------------------------------------------------------------
        $display("\nCWE-1189/1256/1262: Block unprivileged/non-secure access");

        // Privileged write
        priv_level = 2'b11;
        secure_domain = 1'b1;
        addr = 2'b00;
        secret_key_in = 128'hBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB;
        write_req = 1; #10 write_req = 0;

        // Unprivileged read attempt
        priv_level = 2'b00; // unprivileged
        secure_domain = 1'b0; // non-secure
        read_req = 1; #10 read_req = 0;
        $display("Unprivileged read, secret_key_out = %h (should be 0)", secret_key_out);

        // Unprivileged write attempt
        addr = 2'b10;
        secret_key_in = 128'hCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC;
        write_req = 1; #10 write_req = 0;

        // Back to privileged, secure read
        priv_level = 2'b11;
        secure_domain = 1'b1;
        addr = 2'b00;
        read_req = 1; #10 read_req = 0;
        $display("Privileged read after unprivileged write attempt, secret_key_out = %h (should be masked original key, not C's)",
                 secret_key_out);

        // ------------------------------------------------------------
        // CWE-1262: Lock keys (write-once lock for reads)
        // ------------------------------------------------------------
        $display("\nCWE-1262: Lock keys and deny further reads");

        lock_keys = 1'b1;
        addr = 2'b00;
        read_req = 1; #10 read_req = 0;
        $display("Read with lock_keys=1, secret_key_out = %h (should be 0)", secret_key_out);

        // ------------------------------------------------------------
        // CWE-1300: Basic masking on output
        // ------------------------------------------------------------
        $display("\nCWE-1300: Masked output reduces direct key correlation");

        lock_keys = 1'b0;
        addr = 2'b00;
        read_req = 1; #10 read_req = 0;
        $display("Masked key output = %h (should differ from raw stored key)", secret_key_out);

        $display("\n=== END OF SECURE TESTS ===\n");
        $finish;
    end

endmodule
