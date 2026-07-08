`timescale 1ns/1ps

module tb_test_vuln;

    reg         clk;
    reg         rst_n;
    reg  [7:0]  base;
    reg  [7:0]  secret_key;
    wire [15:0] result;

    // DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .base(base),
        .secret_key(secret_key),
        .result(result)
    );

    // Clock generation (allows glitch injection)
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    // Task: inject a clock glitch (CWE‑1247)
    task inject_clk_glitch;
        begin
            #1 clk = ~clk;   // short pulse
            #1 clk = ~clk;   // return to normal
        end
    endtask

    // Task: inject reset glitch (CWE‑1247)
    task inject_reset_glitch;
        begin
            rst_n = 0;
            #1 rst_n = 1;
        end
    endtask

    initial begin
        $display("=== CWE Vulnerability Testbench Start ===");

        // -------------------------------
        // Test 1: CWE‑226 – Sensitive data not cleared
        // -------------------------------
        $display("\n[CWE‑226] Testing lack of scrubbing...");
        rst_n      = 0;
        secret_key = 8'hA5;
        base       = 8'h03;
        #20 rst_n  = 1;

        // Wait for computation to finish
        repeat(20) @(posedge clk);

        $display("Result after computation: %h", result);
        $display("Now reloading new secret WITHOUT clearing...");

        rst_n      = 0;
        secret_key = 8'h5A;   // new key
        base       = 8'h07;   // new base
        #20 rst_n  = 1;

        repeat(20) @(posedge clk);

        $display("Result after reuse: %h", result);
        $display("If result/base_reg still contain old key influence → CWE‑226 confirmed.");

        // -------------------------------
        // Test 2: CWE‑1247 – Glitch attacks
        // -------------------------------
        $display("\n[CWE‑1247] Injecting clock glitch during key-dependent branch...");
        rst_n      = 0;
        secret_key = 8'h81;   // MSB and LSB set → branch active early
        base       = 8'h02;
        #20 rst_n  = 1;

        @(posedge clk);
        inject_clk_glitch;   // glitch during multiply decision

        repeat(10) @(posedge clk);
        $display("Result after glitch: %h", result);
        $display("If glitch changes control flow or result → CWE‑1247 confirmed.");

        // -------------------------------
        // Test 3: CWE‑1256 – Unprivileged access to sensitive hardware
        // -------------------------------
        $display("\n[CWE‑1256] Simulating unprivileged writes to secret_key/base...");
        secret_key = 8'hFF;  // attacker-controlled
        base       = 8'hFF;  // attacker-controlled
        rst_n      = 0;
        #10 rst_n  = 1;

        repeat(10) @(posedge clk);
        $display("Result with attacker-controlled inputs: %h", result);
        $display("If module accepts unprivileged inputs → CWE‑1256 confirmed.");

        // -------------------------------
        // Test 4: CWE‑1262 – No access control on sensitive registers
        // -------------------------------
        $display("\n[CWE‑1262] Checking if sensitive data is externally observable...");
        $display("Secret key = %h, Result = %h", secret_key, result);
        $display("If result reveals key-dependent behavior → CWE‑1262 confirmed.");

        // -------------------------------
        // Test 5: CWE‑1300 – Side-channel leakage
        // -------------------------------
        $display("\n[CWE‑1300] Measuring timing differences for different keys...");

        rst_n      = 0;
        secret_key = 8'h01;  // 1-bit key → short loop
        base       = 8'h03;
        #20 rst_n  = 1;

        integer cycles_short = 0;
        while (dut.key_reg != 0) begin
            @(posedge clk);
            cycles_short++;
        end

        rst_n      = 0;
        secret_key = 8'hF0;  // many bits → long loop
        base       = 8'h03;
        #20 rst_n  = 1;

        integer cycles_long = 0;
        while (dut.key_reg != 0) begin
            @(posedge clk);
            cycles_long++;
        end

        $display("Short key cycles: %0d", cycles_short);
        $display("Long key cycles : %0d", cycles_long);
        $display("If timing differs based on key → CWE‑1300 confirmed.");

        $display("\n=== CWE Vulnerability Testbench Complete ===");
        $finish;
    end

endmodule

