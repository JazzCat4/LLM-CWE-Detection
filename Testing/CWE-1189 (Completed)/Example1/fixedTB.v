`timescale 1ns/1ps
`include "fixed2.v"

module Ex1_secure_tb;

    reg clk, reset, glitch_detect;

    // CPU interface
    reg        cpu_req;
    reg [7:0]  cpu_addr;
    reg [31:0] cpu_wdata;
    reg        cpu_we;
    wire [31:0] cpu_rdata;

    // Peripheral interface (untrusted)
    reg        periph_req;
    reg [7:0]  periph_addr;
    reg [31:0] periph_wdata;
    reg        periph_we;
    wire [31:0] periph_rdata;

    // DUT
    Ex1_secure dut (
        .clk(clk),
        .reset(reset),
        .glitch_detect(glitch_detect),
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

    // -----------------------------
    // Tasks
    // -----------------------------
    task cpu_write(input [7:0] addr, input [31:0] data);
    begin
        @(posedge clk);
        cpu_req   = 1;
        cpu_we    = 1;
        cpu_addr  = addr;
        cpu_wdata = data;
        @(posedge clk);
        cpu_req   = 0;
        cpu_we    = 0;
    end
    endtask

    task cpu_read(input [7:0] addr);
    begin
        @(posedge clk);
        cpu_req  = 1;
        cpu_we   = 0;
        cpu_addr = addr;
        @(posedge clk);
        cpu_req  = 0;
    end
    endtask

    task periph_write(input [7:0] addr, input [31:0] data);
    begin
        @(posedge clk);
        periph_req   = 1;
        periph_we    = 1;
        periph_addr  = addr;
        periph_wdata = data;
        @(posedge clk);
        periph_req   = 0;
        periph_we    = 0;
    end
    endtask

    task periph_read(input [7:0] addr);
    begin
        @(posedge clk);
        periph_req  = 1;
        periph_we   = 0;
        periph_addr = addr;
        @(posedge clk);
        periph_req  = 0;
    end
    endtask

    // -----------------------------
    // Main test sequence
    // -----------------------------
    initial begin
        clk = 0;
        reset = 1;
        glitch_detect = 0;

        cpu_req = 0; cpu_we = 0;
        periph_req = 0; periph_we = 0;

        #20 reset = 0;

        // ============================
        // CWE-226: Scrubbing on reset
        // ============================
        $display("\n[CWE-226] Testing memory scrubbing FIX...");

        cpu_write(8'h10, 32'hDEADBEEF);   // CPU writes secret
        cpu_read(8'h10);
        $display("CPU read secret (secure mem): %h", cpu_rdata);

        // Reset should scrub secure memory
        reset = 1; #20; reset = 0;

        // Peripheral cannot access secure mem; even if it tries same addr
        periph_read(8'h10);
        $display("Peripheral read after reset (should be 0): %h", periph_rdata);

        // ============================
        // CWE-1189: Isolation
        // ============================
        $display("\n[CWE-1189] Testing isolation FIX...");

        cpu_write(8'h20, 32'hCAFEBABE);   // CPU writes sensitive data
        cpu_read(8'h20);
        $display("CPU read secure data: %h", cpu_rdata);

        // Peripheral tries to read same address (disallowed region)
        periph_read(8'h20);
        $display("Peripheral read secure address (should be 0): %h", periph_rdata);

        // Peripheral uses allowed region (0x80+)
        periph_write(8'h80, 32'hBAD0BAD0);
        periph_read(8'h80);
        $display("Peripheral read own region (allowed): %h", periph_rdata);

        // ============================
        // CWE-1262: Access control
        // ============================
        $display("\n[CWE-1262] Testing access control FIX...");

        cpu_write(8'h30, 32'h12345678);   // CPU writes privileged data
        // Peripheral attempts to overwrite in disallowed region
        periph_write(8'h30, 32'hFFFFFFFF);
        cpu_read(8'h30);
        $display("CPU read privileged data (should remain 12345678): %h",
                 cpu_rdata);

        // ============================
        // CWE-1247: Glitch protection
        // ============================
        $display("\n[CWE-1247] Testing glitch protection FIX...");

        // Inject glitch via glitch_detect
        glitch_detect = 1;
        #10 glitch_detect = 0;

        // During/after glitch, FSM goes to error/safe state; accesses blocked
        cpu_write(8'h40, 32'hAAAA5555);
        periph_write(8'h80, 32'hBBBB6666);

        cpu_read(8'h40);
        periph_read(8'h80);

        $display("CPU sees (should be 0 or safe value): %h", cpu_rdata);
        $display("Peripheral sees (should be 0 or safe value): %h", periph_rdata);

        $display("\nSecure testbench complete.");
        $finish;
    end

endmodule
