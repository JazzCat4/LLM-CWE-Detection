`include "fixed.v"

module tb_test_secure;

    reg         clk;
    reg         rst;
    reg         write_en;
    reg         debug_mode;
    reg  [7:0]  data_in;
    wire [7:0]  protected_reg;

    // Instantiate hardened DUT
    test_secure dut (
        .clk(clk),
        .rst(rst),
        .write_en(write_en),
        .debug_mode(debug_mode),
        .data_in(data_in),
        .protected_reg(protected_reg)
    );

    initial clk = 0;
    always #5 clk = ~clk;

    task step;
    begin
        @(posedge clk);
        #1;
    end
    endtask

    initial begin
        // Init
        rst        = 1'b1;
        write_en   = 1'b0;
        debug_mode = 1'b0;
        data_in    = 8'h00;

        // Reset
        step;
        rst = 1'b0;
        step;
        $display("After reset: protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 1) Normal write when unlocked
        data_in  = 8'hAA;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("Normal write (unlocked): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 2) Lock the register (scrub on lock)
        data_in  = 8'hFF;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("After lock set (scrubbed): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 3) Normal write while locked (should be blocked)
        data_in  = 8'h55;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("Normal write while locked (blocked): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 4) Debug write while locked (should also be blocked now)
        debug_mode = 1'b1;
        data_in    = 8'h33;
        step;
        debug_mode = 1'b0;
        $display("Debug write while locked (blocked): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 5) Reset should NOT clear lock_bit
        rst = 1'b1;
        step;
        rst = 1'b0;
        step;
        $display("After reset (lock not preserved): protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        // 6) Attempt writes after reset while still locked
        data_in  = 8'hA5;
        write_en = 1'b1;
        step;
        write_en = 1'b0;
        $display("Write after reset while unlocked: protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        debug_mode = 1'b1;
        data_in    = 8'h5A;
        step;
        debug_mode = 1'b0;
        $display("Debug after reset while unlocked: protected_reg=%h lock_bit=%b",
                 protected_reg, dut.lock_bit);

        $display("Secure testbench completed.");
        $finish;
    end

endmodule
