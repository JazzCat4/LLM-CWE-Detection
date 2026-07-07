`timescale 1ns/1ps

module test_tb;

    reg clk;
    reg rst_n;
    reg en;
    reg we;
    reg [2:0] addr;
    reg [31:0] wdata;
    wire [31:0] rdata;

    // DUT
    test dut (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .we(we),
        .addr(addr),
        .wdata(wdata),
        .rdata(rdata)
    );

    // Clock
    always #5 clk = ~clk;

    // Task: write key
    task write_key(input [2:0] a, input [31:0] d);
    begin
        en = 1; we = 1; addr = a; wdata = d;
        @(posedge clk);
    end
    endtask

    // Task: read key
    task read_key(input [2:0] a);
    begin
        en = 1; we = 0; addr = a;
        @(posedge clk);
        $display("READ addr=%0d -> %h", a, rdata);
    end
    endtask

    initial begin
        clk = 0;
        rst_n = 0;
        en = 0;
        we = 0;
        addr = 0;
        wdata = 0;

        // ============================================================
        // CWE‑226 TESTS — Sensitive data not cleared before reuse
        // ============================================================

        $display("\n--- CWE‑226: Sensitive Information Not Removed Before Reuse ---");

        // 1. Write a key
        rst_n = 1;
        @(posedge clk);
        write_key(0, 32'hDEADBEEF);

        // 2. Read it back
        read_key(0);

        // 3. Assert reset — key_buf should clear, but rdata_reg SHOULD also clear (it doesn't)
        rst_n = 0;
        @(posedge clk);

        // 4. After reset, rdata still holds stale secret
        $display("After reset, rdata_reg STILL = %h (should be 0)", rdata);

        rst_n = 1;
        @(posedge clk);

        // 5. Idle mode — no scrubbing occurs
        en = 0; we = 0;
        @(posedge clk);
        $display("Idle mode: rdata STILL = %h (should be scrubbed)", rdata);

        // ============================================================
        // CWE‑1256 TESTS — Unprivileged access to sensitive hardware
        // ============================================================

        $display("\n--- CWE‑1256: Improper Restriction of Software Interfaces ---");

        // No privilege bits exist, so ANY write is allowed
        write_key(1, 32'hCAFEBABE);
        read_key(1);

        // Simulate “unprivileged” access by simply toggling signals
        en = 1; we = 1; addr = 2; wdata = 32'hBAD0C0DE;
        @(posedge clk);
        read_key(2);

        $display("Unprivileged write/read succeeded (should fault or deny)");

        // ============================================================
        // CWE‑1262 TESTS — Improper Access Control for Register Interface
        // ============================================================

        $display("\n--- CWE‑1262: Improper Access Control for Register Interface ---");

        // 1. Reads of sensitive registers are allowed without restriction
        read_key(0);
        read_key(1);
        read_key(2);

        // 2. Writes allowed without restriction
        write_key(3, 32'h12345678);
        read_key(3);

        // 3. Out‑of‑range address → default-open behavior
        addr = 5; en = 1; we = 0;
        @(posedge clk);
        $display("Read addr=5 -> %h (default-open behavior)", rdata);

        // ============================================================
        // CWE‑1300 TESTS — Side-channel considerations
        // ============================================================

        $display("\n--- CWE‑1300: Physical Side-Channel Weaknesses ---");

        // This module has no constant-time protections.
        // We demonstrate that key-dependent switching occurs directly.

        write_key(0, 32'h00000000);
        read_key(0);

        write_key(0, 32'hFFFFFFFF);
        read_key(0);

        $display("Different key values cause different switching activity (visible in waveform).");

        $display("\n--- TEST COMPLETE ---");
        $finish;
    end

endmodule
