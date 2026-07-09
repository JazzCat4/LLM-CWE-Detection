`timescale 1ns/1ps

module tb_test_security;

    reg clk, rst, start;
    reg [31:0] base, exponent;
    wire [31:0] result;
    wire done;

    // DUT
    test dut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .base(base),
        .exponent(exponent),
        .result(result),
        .done(done)
    );

    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;   // 100 MHz nominal clock
    end

    // Main stimulus
    initial begin
        $display("=== CWE Security Testbench Start ===");

        // ------------------------------------------------------------
        // CWE‑226: Sensitive registers not cleared on reset
        // ------------------------------------------------------------
        $display("\n[CWE‑226] Testing stale register retention across reset");

        // First operation
        rst = 1; start = 0; base = 32'hAAAA_BBBB; exponent = 32'h0000_0003;
        #12 rst = 0;

        start = 1; #10 start = 0;
        wait(done);

        $display("First result: %h", result);

        // Trigger reset — base_reg and exp_reg should clear but do NOT
        rst = 1; #10 rst = 0;

        // Second operation with different inputs
        base = 32'h1111_2222;
        exponent = 32'h0000_0002;
        start = 1; #10 start = 0;

        wait(done);

        $display("Second result: %h", result);
        $display("If second result is influenced by first inputs, CWE‑226 confirmed.");

        // ------------------------------------------------------------
        // CWE‑1247: Clock glitch / illegal FSM state injection
        // ------------------------------------------------------------
        $display("\n[CWE‑1247] Injecting clock glitch to force illegal FSM state");

        rst = 1; #10 rst = 0;
        base = 32'h0000_0002;
        exponent = 32'h0000_0008;

        start = 1; #10 start = 0;

        // Inject a glitch: extra clock edge
        #17 clk = 1; #1 clk = 0;  // unnatural pulse

        // Observe whether FSM enters illegal state or misbehaves
        repeat(20) @(posedge clk);

        $display("If FSM stalls, miscomputes, or exits early, CWE‑1247 confirmed.");

        // ------------------------------------------------------------
        // CWE‑1300: Side‑channel timing leakage
        // ------------------------------------------------------------
        $display("\n[CWE‑1300] Measuring timing variation based on exponent bits");

        rst = 1; #10 rst = 0;

        // Case 1: exponent with many 1 bits
        exponent = 32'hFFFF_FFFF;
        base = 32'h0000_0002;
        start = 1; #10 start = 0;

        time start_time = $time;
        wait(done);
        time end_time = $time;
        $display("High‑Hamming‑weight exponent cycles: %0d", end_time - start_time);

        // Case 2: exponent with few 1 bits
        rst = 1; #10 rst = 0;
        exponent = 32'h0000_0001;
        base = 32'h0000_0002;
        start = 1; #10 start = 0;

        start_time = $time;
        wait(done);
        end_time = $time;
        $display("Low‑Hamming‑weight exponent cycles: %0d", end_time - start_time);

        $display("If timing differs significantly, CWE‑1300 confirmed.");

        $display("\n=== CWE Security Testbench Complete ===");
        $finish;
    end

endmodule
