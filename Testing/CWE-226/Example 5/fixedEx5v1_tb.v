`timescale 1ns/1ps

module test_secure_tb;

    reg clk;
    reg rst_n;
    reg en;
    reg we;
    reg priv;
    reg lock_set;
    reg [2:0] addr;
    reg [31:0] wdata;
    wire [31:0] rdata;
    wire fault;

    test_secure dut (
        .clk(clk),
        .rst_n(rst_n),
        .en(en),
        .we(we),
        .priv(priv),
        .lock_set(lock_set),
        .addr(addr),
        .wdata(wdata),
        .rdata(rdata),
        .fault(fault)
    );

    always #5 clk = ~clk;

    task write_key(input [2:0] a, input [31:0] d, input p);
    begin
        en = 1; we = 1; priv = p; addr = a; wdata = d;
        @(posedge clk);
        $display("WRITE addr=%0d priv=%0b fault=%0b", a, p, fault);
    end
    endtask

    task read_reg(input [2:0] a, input p);
    begin
        en = 1; we = 0; priv = p; addr = a;
        @(posedge clk);
        $display("READ addr=%0d priv=%0b -> %h fault=%0b", a, p, rdata, fault);
    end
    endtask

    integer i;

    initial begin
        clk = 0;
        rst_n = 0;
        en = 0;
        we = 0;
        priv = 0;
        lock_set = 0;
        addr = 0;
        wdata = 0;

        // Reset: scrub all secrets
        @(posedge clk);
        rst_n = 1;
        @(posedge clk);

        // CWE-1262/1256: privileged write allowed
        write_key(0, 32'hDEADBEEF, 1'b1);

        // Lock keys (write-once)
        lock_set = 1;
        @(posedge clk);
        lock_set = 0;

        // Attempt privileged write after lock: should fault and not modify
        write_key(0, 32'hCAFEBABE, 1'b1);

        // Unprivileged write: should fault
        write_key(1, 32'hBAD0C0DE, 1'b0);

        // Reads: should never expose key contents, only status
        read_reg(0, 1'b1);
        read_reg(1, 1'b1);

        // CWE-226: disable en → scrub secrets
        en = 0; we = 0;
        @(posedge clk);
        read_reg(0, 1'b1);

        // Out-of-range address: default-deny, fault
        read_reg(5, 1'b1);

        $display("\n--- SECURE TEST COMPLETE ---");
        $finish;
    end

endmodule
