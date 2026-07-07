`timescale 1ns/1ps

module tb_secret_fifo;

    reg clk, rst;
    reg push, pop;
    reg [63:0] secret_in;
    wire [63:0] secret_out;
    wire empty, full;

    // DUT
    secret_fifo dut (
        .clk(clk),
        .rst(rst),
        .push(push),
        .pop(pop),
        .secret_in(secret_in),
        .secret_out(secret_out),
        .empty(empty),
        .full(full)
    );

    // Clock
    always #5 clk = ~clk;

    initial begin
        $display("=== SECURITY TESTBENCH START ===");
        clk = 0;
        rst = 0;
        push = 0;
        pop = 0;
        secret_in = 64'h0;

        // ------------------------------------------------------------
        // TEST 1 — CWE‑226: Sensitive information not removed on reset
        // ------------------------------------------------------------
        $display("\n[CWE‑226] Testing stale secret persistence across reset");

        // Write a secret
        @(posedge clk);
        secret_in = 64'hDEADBEEFCAFEBABE;
        push = 1;
        @(posedge clk);
        push = 0;

        // Pop it out
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        // Now reset the FIFO
        @(posedge clk);
        rst = 1;
        @(posedge clk);
        rst = 0;

        // Try popping again — if stale data appears, vulnerability confirmed
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE‑226] secret_out after reset pop = %h (should be 0 if scrubbed)", secret_out);

        // ------------------------------------------------------------
        // TEST 2 — CWE‑1189: No isolation between trust domains
        // ------------------------------------------------------------
        $display("\n[CWE‑1189] Testing untrusted agent overwriting trusted secrets");

        // Trusted agent writes a secret
        @(posedge clk);
        secret_in = 64'h1111222233334444;
        push = 1;
        @(posedge clk);
        push = 0;

        // Untrusted agent overwrites it (no access control)
        @(posedge clk);
        secret_in = 64'hBAD0BAD0BAD0BAD0;
        push = 1;
        @(posedge clk);
        push = 0;

        // Pop — if untrusted data appears, isolation failure confirmed
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE‑1189] secret_out = %h (should NOT allow untrusted overwrite)", secret_out);

        // ------------------------------------------------------------
        // TEST 3 — CWE‑1262: No access control on register-like interface
        // ------------------------------------------------------------
        $display("\n[CWE‑1262] Testing unrestricted read/write access");

        // Write secret
        @(posedge clk);
        secret_in = 64'hAAAAAAAAAAAAAAAA;
        push = 1;
        @(posedge clk);
        push = 0;

        // Untrusted read (pop)
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE‑1262] Untrusted read returned = %h (should be masked or denied)", secret_out);

        // ------------------------------------------------------------
        // TEST 4 — CWE‑226 + CWE‑1189: Reset desynchronization + stale secret leak
        // ------------------------------------------------------------
        $display("\n[CWE‑226 + CWE‑1189] Testing stale secret exposure after reset desync");

        // Write secret
        @(posedge clk);
        secret_in = 64'hFEEDFACECAFED00D;
        push = 1;
        @(posedge clk);
        push = 0;

        // Reset before pop — memory not scrubbed
        @(posedge clk);
        rst = 1;
        @(posedge clk);
        rst = 0;

        // Pop — stale secret may leak
        @(posedge clk);
        pop = 1;
        @(posedge clk);
        pop = 0;

        $display("[CWE‑226/CWE‑1189] secret_out after reset = %h (should NOT leak stale secret)", secret_out);

        $display("\n=== SECURITY TESTBENCH END ===");
        $finish;
    end

endmodule
