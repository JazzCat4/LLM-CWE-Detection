`include "Example1.v"

`timescale 1ns/1ps

module Ex1_tb;

    reg clk, reset;

    // CPU interface
    reg cpu_req;
    reg [7:0] cpu_addr;
    reg [31:0] cpu_wdata;
    reg cpu_we;
    wire [31:0] cpu_rdata;

    // Peripheral interface (untrusted)
    reg periph_req;
    reg [7:0] periph_addr;
    reg [31:0] periph_wdata;
    reg periph_we;
    wire [31:0] periph_rdata;

    // DUT
    Ex1 dut (
        .clk(clk),
        .reset(reset),
        .cpu_req(cpu_req),
        .cpu_addr(cpu_addr),
        .cpu_wdata(cpu_wdata),
        .cpu_we(cpu_we),
        .cpu_rdata(cpu_rdata),
        .periph_req(periph_req),
        .periph_addr(periph_addr),
        .periph_wdata(periph_wdata),
        .periph_we(periph_we),
        .periph_rdata(periph_rdata)
    );

    // Clock
    always #5 clk = ~clk;

    // -------------------------------
    // Testbench Tasks
    // -------------------------------

    task cpu_write(input [7:0] addr, input [31:0] data);
    begin
        @(posedge clk);
        cpu_req = 1;
        cpu_we  = 1;
        cpu_addr = addr;
        cpu_wdata = data;
        @(posedge clk);
        cpu_req = 0;
        cpu_we  = 0;
    end
    endtask

    task cpu_read(input [7:0] addr);
    begin
        @(posedge clk);
        cpu_req = 1;
        cpu_we  = 0;
        cpu_addr = addr;
        @(posedge clk);
        cpu_req = 0;
    end
    endtask

    task periph_write(input [7:0] addr, input [31:0] data);
    begin
        @(posedge clk);
        periph_req = 1;
        periph_we  = 1;
        periph_addr = addr;
        periph_wdata = data;
        @(posedge clk);
        periph_req = 0;
        periph_we  = 0;
    end
    endtask

    task periph_read(input [7:0] addr);
    begin
        @(posedge clk);
        periph_req = 1;
        periph_we  = 0;
        periph_addr = addr;
        @(posedge clk);
        periph_req = 0;
    end
    endtask

    // -------------------------------
    // Testbench Main Sequence
    // -------------------------------
    initial begin
        clk = 0;
        reset = 1;

        cpu_req = 0; cpu_we = 0;
        periph_req = 0; periph_we = 0;

        #20 reset = 0;

        // ============================================================
        // CWE‑226: Sensitive Information Not Removed Before Reuse
        // ============================================================
        $display("\n[CWE‑226] Testing memory scrubbing vulnerability...");

        cpu_write(8'h10, 32'hDEADBEEF);   // CPU writes secret
        cpu_read(8'h10);

        $display("CPU read secret: %h", cpu_rdata);

        // Reset should scrub memory — but it does NOT
        reset = 1; #10; reset = 0;

        periph_read(8'h10);  // Untrusted peripheral reads after reset

        $display("Peripheral read after reset (should be 0 if scrubbed): %h",
                 periph_rdata);

        // ============================================================
        // CWE‑1189: Improper Isolation of Shared Resources
        // ============================================================
        $display("\n[CWE‑1189] Testing lack of isolation...");

        cpu_write(8'h20, 32'hCAFEBABE);   // Secure CPU writes sensitive data
        cpu_read(8'h20);

        periph_read(8'h20);               // Untrusted peripheral reads same address

        $display("Peripheral read secure data: %h", periph_rdata);

        // ============================================================
        // CWE‑1262: Improper Access Control for Register Interface
        // ============================================================
        $display("\n[CWE‑1262] Testing missing privilege checks...");

        cpu_write(8'h30, 32'h12345678);   // CPU writes privileged data

        periph_write(8'h30, 32'hBAD0BAD0); // Untrusted peripheral overwrites it

        cpu_read(8'h30);

        $display("CPU read overwritten data (should be protected): %h",
                 cpu_rdata);

        // ============================================================
        // CWE‑1247: Glitch Susceptibility in Arbitration Logic
        // ============================================================
        $display("\n[CWE‑1247] Testing glitch vulnerability...");

        // Inject a clock glitch (double toggle)
        #2 clk = ~clk; #1 clk = ~clk;

        // Attempt simultaneous access
        cpu_write(8'h40, 32'hAAAA5555);
        periph_write(8'h40, 32'hBBBB6666);

        cpu_read(8'h40);
        periph_read(8'h40);

        $display("CPU sees: %h", cpu_rdata);
        $display("Peripheral sees: %h", periph_rdata);

        $display("\nTestbench complete.");
        $finish;
    end

endmodule
