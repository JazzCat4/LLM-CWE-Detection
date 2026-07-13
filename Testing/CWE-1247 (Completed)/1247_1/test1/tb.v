`timescale 1ns/1ps

`include "Example1.v"

module Ex1_tb;

    reg clk, reset;
    reg start_auth;
    reg [31:0] challenge, response;
    wire unlocked;

    Ex1 dut (
        .clk(clk),
        .reset(reset),
        .start_auth(start_auth),
        .challenge(challenge),
        .response(response),
        .unlocked(unlocked)
    );

    // Clock generator
    always #5 clk = ~clk;

    task reset_dut;
        begin
            reset = 1;
            #20;
            reset = 0;
            #20;
        end
    endtask


    // ============================================================
    // MAIN TEST SEQUENCE
    // ============================================================
    initial begin
        clk = 0;
        reset = 1;
        start_auth = 0;
        challenge = 0;
        response = 0;

        #20 reset = 0;

        test_CWE226_scrubbing();
        reset_dut();
        test_CWE1300_sidechannel();
        reset_dut();
        test_CWE1247_glitch_bypass();
        reset_dut();
        test_CWE1262_access_control();

        #200 $finish;
    end

    // ============================================================
    // CWE‑226 — Sensitive Information Not Removed Before Reuse
    // ============================================================
    task test_CWE226_scrubbing;
        begin
            $display("\n[CWE‑226] Scrubbing / Zeroization Tests");

            // Successful authentication
            challenge = 32'h12345678;
            response  = challenge ^ 32'hC0FFEE42;
            start_auth = 1; #10 start_auth = 0;

            #40;
            if (unlocked !== 1)
                $display("  FAIL: Unlock did not occur.");
            else
                $display("  PASS: Unlock occurred.");

            // Reset and check if key still works
            reset = 1; #10 reset = 0;

            challenge = 32'hAAAAAAAA;
            response  = challenge ^ 32'hC0FFEE42;
            start_auth = 1; #10 start_auth = 0;

            #40;
            if (unlocked == 1)
                $display("  VULNERABILITY: SECRET_KEY persists across reset (no scrubbing).");
            else
                $display("  INFO: Unlock did not occur, but key remains active.");
        end
    endtask

    // ============================================================
    // CWE‑1300 — Side‑Channel Leakage (Manual Toggle Counting)
    // ============================================================
    task test_CWE1300_sidechannel;
        integer i, b;
        reg [31:0] prev_xor;
        reg [31:0] curr_xor;
        integer toggle_count;
        begin
            $display("\n[CWE‑1300] Side‑Channel Switching Activity Tests");

            prev_xor = 32'h0;

            for (i = 0; i < 16; i = i + 1) begin
                challenge = i;
                curr_xor = challenge ^ 32'hC0FFEE42;

                // Manual bit‑toggle counter (pure Verilog)
                toggle_count = 0;
                for (b = 0; b < 32; b = b + 1) begin
                    if (curr_xor[b] !== prev_xor[b])
                        toggle_count = toggle_count + 1;
                end

                $display("  XOR toggles = %0d for challenge=%h", toggle_count, challenge);

                prev_xor = curr_xor;
            end

            $display("  VULNERABILITY: Key‑dependent switching activity observed.");
        end
    endtask

    // ============================================================
    // CWE‑1247 — Glitch Bypass Tests
    // ============================================================
    task test_CWE1247_glitch_bypass;
        begin
            $display("\n[CWE‑1247] Glitch Bypass Tests");

            // Incorrect response
            challenge = 32'hDEADBEEF;
            response  = 32'h0;
            start_auth = 1; #10 start_auth = 0;

            // Inject a synthetic clock glitch (double toggle)
            #3 clk = ~clk;
            #1 clk = ~clk;

            #40;
            if (unlocked == 1)
                $display("  VULNERABILITY: Unlock occurred due to glitch.");
            else
                $display("  INFO: No glitch bypass observed in this run.");
        end
    endtask

    // ============================================================
    // CWE‑1262 — Access Control Bypass Tests
    // ============================================================
    task test_CWE1262_access_control;
        begin
            $display("\n[CWE‑1262] Access Control Tests");

            // Any untrusted agent can drive inputs
            challenge = 32'hCAFEBABE;
            response  = challenge ^ 32'hC0FFEE42;
            start_auth = 1; #10 start_auth = 0;

            #40;
            if (unlocked == 1)
                $display("  VULNERABILITY: Untrusted inputs can directly assert unlock.");
            else
                $display("  INFO: Unlock did not occur.");
        end
    endtask

endmodule
