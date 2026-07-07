`timescale 1ns/1ps

module tb_secret_fifo_secure;

    reg clk, rst;
    reg push, pop;
    reg [63:0] secret_in;
    wire [63:0] secret_out;
    wire empty, full;

    reg secure_write_en;
    reg secure_read_en;
    reg domain_switch;

    // DUT
    secret_fifo_secure dut (
        .clk(clk),
        .rst(rst),
        .push(push),
        .pop(pop),
        .secret_in(secret_in),
        .secret_out(secret_out),
        .empty(empty),
        .full(full),
        .secure_write_en(secure_write_en),
        .secure_read_en(secure_read_en),
        .domain_switch(domain_switch)
    );

    // Clock
    always #5 clk = ~clk;

    initial begin
        $display("=== SECURE FIFO SECURITY TESTBENCH START ===");
        clk = 0;
        rst = 0;
        push = 0;
        pop = 0;
        secret_in = 64'h0;
        secure_write_en = 0;
        secure_read_en  = 0;
        domain_switch   = 0;

        // -----------------------------
        // TEST 1 — CWE-226: reset scrub
        // -----------------------------
        $display("\n[CWE-226] Testing scrub on reset");

        // Trusted write + read
        secure_write_en = 1;
        secure_read_en  = 1;

        @(posedge clk);
        secret_in = 64'hDEADBEEFCAFEBABE;
        push = 1;
        @(posedge clk);
        push = 0;

        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        // Reset: should scrub secrets
        @(posedge clk);
        rst = 1;
        @(posedge clk);
        rst = 0;

        // Try to pop again: should be 0 (no stale secret)
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE-226] secret_out after reset pop = %h (expected 0)", secret_out);

        // -----------------------------------------
        // TEST 2 — CWE-1189: untrusted overwrite blocked
        // -----------------------------------------
        $display("\n[CWE-1189] Testing isolation between trusted and untrusted writers");

        // Trusted agent writes
        secure_write_en = 1;
        secure_read_en  = 1;
        @(posedge clk);
        secret_in = 64'h1111222233334444;
        push = 1;
        @(posedge clk);
        push = 0;

        // Untrusted agent (no write privilege) attempts overwrite
        secure_write_en = 0;
        @(posedge clk);
        secret_in = 64'hBAD0BAD0BAD0BAD0;
        push = 1;
        @(posedge clk);
        push = 0;

        // Pop: should return trusted value, not untrusted
        secure_read_en = 1;
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE-1189] secret_out = %h (expected 1111222233334444)", secret_out);

        // -----------------------------------------
        // TEST 3 — CWE-1262: untrusted read masked
        // -----------------------------------------
        $display("\n[CWE-1262] Testing read access control");

        // Trusted write
        secure_write_en = 1;
        @(posedge clk);
        secret_in = 64'hAAAAAAAAAAAAAAAA;
        push = 1;
        @(posedge clk);
        push = 0;

        // Untrusted read (no read privilege)
        secure_read_en = 0;
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE-1262] secret_out (untrusted read) = %h (expected 0)", secret_out);

        // -----------------------------------------
        // TEST 4 — CWE-226 + CWE-1189: domain switch scrub
        // -----------------------------------------
        $display("\n[CWE-226 + CWE-1189] Testing scrub on domain switch");

        // Trusted domain writes secret
        secure_write_en = 1;
        secure_read_en  = 1;
        @(posedge clk);
        secret_in = 64'hFEEDFACECAFED00D;
        push = 1;
        @(posedge clk);
        push = 0;

        // Domain switch: should scrub secrets
        @(posedge clk);
        domain_switch = 1;
        @(posedge clk);
        domain_switch = 0;

        // New (possibly untrusted) domain tries to read
        secure_read_en = 0; // no privilege
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE-226/CWE-1189] secret_out after domain switch = %h (expected 0)", secret_out);

        $display("\n=== SECURE FIFO SECURITY TESTBENCH END ===");
        $finish;
    end

endmodule
