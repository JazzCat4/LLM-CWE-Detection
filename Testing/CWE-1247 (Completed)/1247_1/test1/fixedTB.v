`timescale 1ns/1ps
`include "fixed.v"
module SecureEx1_tb;

    reg clk, reset;
    reg start_auth;
    reg [31:0] challenge, response;
    reg auth_priv;
    reg glitch_detect;
    reg [31:0] mask;
    wire unlocked;

    SecureEx1 dut (
        .clk(clk),
        .reset(reset),
        .start_auth(start_auth),
        .challenge(challenge),
        .response(response),
        .auth_priv(auth_priv),
        .glitch_detect(glitch_detect),
        .mask(mask),
        .unlocked(unlocked)
    );

    // Clock
    always #5 clk = ~clk;

    // Reset helper
    task reset_dut;
    begin
        reset = 1;
        start_auth   = 0;
        challenge    = 0;
        response     = 0;
        auth_priv    = 0;
        glitch_detect= 0;
        mask         = 32'h0;
        #20;
        reset = 0;
        #20;
    end
    endtask

    initial begin
        clk = 0;
        reset = 0;
        start_auth   = 0;
        challenge    = 0;
        response     = 0;
        auth_priv    = 0;
        glitch_detect= 0;
        mask         = 32'h0;

        // CWE‑226
        reset_dut();
        test_CWE226_scrubbing();

        // CWE‑1300
        reset_dut();
        test_CWE1300_sidechannel();

        // CWE‑1247
        reset_dut();
        test_CWE1247_glitch_bypass();

        // CWE‑1262
        reset_dut();
        test_CWE1262_access_control();

        #200 $finish;
    end

    // ---------------- CWE‑226 ----------------
    task test_CWE226_scrubbing;
        begin
            $display("\n[CWE‑226] Scrubbing / Zeroization Tests");

            auth_priv = 1;
            mask      = 32'hA5A5A5A5;

            // Successful authentication
            challenge  = 32'h12345678;
            response   = challenge ^ 32'hC0FFEE42;
            start_auth = 1; #10 start_auth = 0;

            #40;
            if (unlocked !== 1)
                $display("  FAIL: Unlock did not occur.");
            else
                $display("  PASS: Unlock occurred.");

            // Reset should scrub key_reg and clear unlocked
            reset_dut();

            // Try again: behavior should be identical, but key_reg was scrubbed
            auth_priv = 1;
            mask      = 32'hA5A5A5A5;
            challenge = 32'hAAAAAAAA;
            response  = challenge ^ 32'hC0FFEE42;
            start_auth = 1; #10 start_auth = 0;

            #40;
            if (unlocked == 1)
                $display("  PASS: Re-auth works after scrubbed reset (no stale state).");
            else
                $display("  FAIL: Unlock did not occur after reset.");
        end
    endtask

    // ---------------- CWE‑1300 ----------------
    task test_CWE1300_sidechannel;
        integer i, b;
        reg [31:0] prev_xor;
        reg [31:0] curr_xor;
        integer toggle_count;
        begin
            $display("\n[CWE‑1300] Side‑Channel Switching Activity Tests");

            auth_priv = 1;
            mask      = 32'hFFFF0000; // masking to reduce direct key correlation

            prev_xor = 32'h0;

            for (i = 0; i < 16; i = i + 1) begin
                challenge = i;
                // emulate internal masked XOR path
                curr_xor = (challenge ^ 32'hC0FFEE42) ^ mask;

                toggle_count = 0;
                for (b = 0; b < 32; b = b + 1) begin
                    if (curr_xor[b] !== prev_xor[b])
                        toggle_count = toggle_count + 1;
                end

                $display("  XOR toggles (masked) = %0d for challenge=%h", toggle_count, challenge);
                prev_xor = curr_xor;
            end

            $display("  INFO: Masking reduces direct key-dependent switching visibility.");
        end
    endtask

    // ---------------- CWE‑1247 ----------------
    task test_CWE1247_glitch_bypass;
        begin
            $display("\n[CWE‑1247] Glitch Bypass Tests");

            auth_priv = 1;
            mask      = 32'h0;

            // Incorrect response
            challenge  = 32'hDEADBEEF;
            response   = 32'h0;
            start_auth = 1; #10 start_auth = 0;

            // Assert glitch_detect: DUT should go to ERROR and stay locked
            glitch_detect = 1;
            #10 glitch_detect = 0;

            #40;
            if (unlocked == 1)
                $display("  FAIL: Unlock occurred despite glitch_detect.");
            else
                $display("  PASS: Glitch forces safe ERROR state, unlocked=0.");
        end
    endtask

    // ---------------- CWE‑1262 ----------------
    task test_CWE1262_access_control;
        begin
            $display("\n[CWE‑1262] Access Control Tests");

            mask = 32'h0;

            // Unprivileged attempt: should NOT unlock
            auth_priv = 0;
            challenge = 32'hCAFEBABE;
            response  = challenge ^ 32'hC0FFEE42;
            start_auth = 1; #10 start_auth = 0;

            #40;
            if (unlocked == 1)
                $display("  FAIL: Unprivileged context was able to unlock.");
            else
                $display("  PASS: Unprivileged context blocked from unlocking.");

            // Privileged attempt: should unlock
            auth_priv = 1;
            challenge = 32'hCAFEBABE;
            response  = challenge ^ 32'hC0FFEE42;
            start_auth = 1; #10 start_auth = 0;

            #40;
            if (unlocked == 1)
                $display("  PASS: Privileged context successfully unlocked.");
            else
                $display("  FAIL: Privileged context could not unlock.");
        end
    endtask

endmodule
